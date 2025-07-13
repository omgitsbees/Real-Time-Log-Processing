import apache_log_parser
import json
from datetime import datetime, timedelta
import logging
from pathlib import Path
import yaml
from kafka import KafkaProducer, KafkaConsumer
from elasticsearch import Elasticsearch
import time
import signal
import sys
import threading
from typing import Dict, List, Optional, Callable
from dataclasses import dataclass, asdict
import hashlib
import os
from collections import defaultdict, deque
import psutil
import geoip2.database
import re
from contextlib import contextmanager
import sqlite3
from concurrent.futures import ThreadPoolExecutor, as_completed
import asyncio
import aiohttp
import redis
from prometheus_client import Counter, Histogram, Gauge, start_http_server
import structlog

# Configure structured logging
structlog.configure(
    processors=[
        structlog.stdlib.filter_by_level,
        structlog.stdlib.add_logger_name,
        structlog.stdlib.add_log_level,
        structlog.stdlib.PositionalArgumentsFormatter(),
        structlog.processors.TimeStamper(fmt="iso"),
        structlog.processors.StackInfoRenderer(),
        structlog.processors.format_exc_info,
        structlog.processors.JSONRenderer()
    ],
    wrapper_class=structlog.stdlib.BoundLogger,
    logger_factory=structlog.stdlib.LoggerFactory(),
    cache_logger_on_first_use=True,
)

logger = structlog.get_logger()

# Prometheus metrics
LOGS_PROCESSED = Counter('logs_processed_total', 'Total logs processed')
LOGS_FAILED = Counter('logs_failed_total', 'Total logs failed to process')
PROCESSING_TIME = Histogram('log_processing_seconds', 'Time spent processing logs')
ACTIVE_CONNECTIONS = Gauge('active_connections', 'Number of active connections')
KAFKA_LAG = Gauge('kafka_consumer_lag', 'Kafka consumer lag')
ELASTICSEARCH_ERRORS = Counter('elasticsearch_errors_total', 'Elasticsearch errors')

@dataclass
class LogEntry:
    """Structured log entry with validation."""
    timestamp: str
    ip_address: str
    method: str
    path: str
    status: int
    bytes_sent: int
    referer: str
    user_agent: str
    processed_at: str
    geo_country: Optional[str] = None
    geo_city: Optional[str] = None
    is_bot: bool = False
    security_threat: bool = False
    response_time: Optional[float] = None
    
    def to_dict(self) -> Dict:
        return asdict(self)

class SecurityAnalyzer:
    """Analyze logs for security threats."""
    
    def __init__(self):
        self.suspicious_patterns = [
            r'\.\./',  # Directory traversal
            r'<script',  # XSS attempts
            r'union.*select',  # SQL injection
            r'etc/passwd',  # File inclusion
            r'cmd\.exe',  # Command injection
        ]
        self.bot_patterns = [
            r'bot|crawler|spider|scraper',
            r'googlebot|bingbot|yahoo',
            r'facebookexternalhit|twitterbot'
        ]
        
    def analyze(self, log_entry: LogEntry) -> LogEntry:
        """Analyze log entry for security threats and bots."""
        # Check for security threats
        combined_text = f"{log_entry.path} {log_entry.user_agent}".lower()
        log_entry.security_threat = any(
            re.search(pattern, combined_text, re.IGNORECASE)
            for pattern in self.suspicious_patterns
        )
        
        # Check for bots
        log_entry.is_bot = any(
            re.search(pattern, log_entry.user_agent, re.IGNORECASE)
            for pattern in self.bot_patterns
        )
        
        return log_entry

class GeoLocationEnricher:
    """Enrich logs with geolocation data."""
    
    def __init__(self, geoip_db_path: str = 'GeoLite2-City.mmdb'):
        self.geoip_db_path = geoip_db_path
        self.reader = None
        self._init_geoip()
    
    def _init_geoip(self):
        """Initialize GeoIP database."""
        try:
            if os.path.exists(self.geoip_db_path):
                self.reader = geoip2.database.Reader(self.geoip_db_path)
                logger.info("GeoIP database loaded successfully")
            else:
                logger.warning("GeoIP database not found, skipping geo enrichment")
        except Exception as e:
            logger.error("Failed to initialize GeoIP database", error=str(e))
    
    def enrich(self, log_entry: LogEntry) -> LogEntry:
        """Add geolocation data to log entry."""
        if not self.reader:
            return log_entry
            
        try:
            response = self.reader.city(log_entry.ip_address)
            log_entry.geo_country = response.country.name
            log_entry.geo_city = response.city.name
        except Exception as e:
            logger.debug("Failed to get geolocation", ip=log_entry.ip_address, error=str(e))
        
        return log_entry

class RateLimiter:
    """Rate limiter for log processing."""
    
    def __init__(self, max_requests: int = 1000, window_seconds: int = 60):
        self.max_requests = max_requests
        self.window_seconds = window_seconds
        self.requests = deque()
        self.lock = threading.Lock()
    
    def is_allowed(self) -> bool:
        """Check if request is allowed based on rate limit."""
        with self.lock:
            now = time.time()
            # Remove old requests outside the window
            while self.requests and self.requests[0] < now - self.window_seconds:
                self.requests.popleft()
            
            if len(self.requests) >= self.max_requests:
                return False
            
            self.requests.append(now)
            return True

class CircuitBreaker:
    """Circuit breaker for external service calls."""
    
    def __init__(self, failure_threshold: int = 5, recovery_timeout: int = 60):
        self.failure_threshold = failure_threshold
        self.recovery_timeout = recovery_timeout
        self.failure_count = 0
        self.last_failure_time = None
        self.state = 'closed'  # closed, open, half-open
        self.lock = threading.Lock()
    
    @contextmanager
    def call(self):
        """Context manager for circuit breaker."""
        if not self._can_call():
            raise Exception("Circuit breaker is open")
        
        try:
            yield
            self._on_success()
        except Exception as e:
            self._on_failure()
            raise
    
    def _can_call(self) -> bool:
        with self.lock:
            if self.state == 'closed':
                return True
            elif self.state == 'open':
                if time.time() - self.last_failure_time > self.recovery_timeout:
                    self.state = 'half-open'
                    return True
                return False
            else:  # half-open
                return True
    
    def _on_success(self):
        with self.lock:
            self.failure_count = 0
            self.state = 'closed'
    
    def _on_failure(self):
        with self.lock:
            self.failure_count += 1
            self.last_failure_time = time.time()
            if self.failure_count >= self.failure_threshold:
                self.state = 'open'

class LogParser:
    """Enhanced log parser with caching and validation."""
    
    def __init__(self, cache_size: int = 10000):
        self.line_parser = apache_log_parser.make_parser(
            "%h %l %u %t \"%r\" %>s %b \"%{Referer}i\" \"%{User-Agent}i\""
        )
        self.cache = {}
        self.cache_size = cache_size
        self.security_analyzer = SecurityAnalyzer()
        self.geo_enricher = GeoLocationEnricher()
        self.rate_limiter = RateLimiter()
    
    def parse_log_line(self, line: str) -> Optional[LogEntry]:
        """Parse a single log line with caching and enrichment."""
        if not self.rate_limiter.is_allowed():
            logger.warning("Rate limit exceeded, dropping log")
            return None
        
        # Check cache first
        line_hash = hashlib.md5(line.encode()).hexdigest()
        if line_hash in self.cache:
            return self.cache[line_hash]
        
        try:
            with PROCESSING_TIME.time():
                parsed = self.line_parser(line)
                
                # Create structured log entry
                log_entry = LogEntry(
                    timestamp=parsed['time_received_utc_isoformat'],
                    ip_address=parsed['remote_host'],
                    method=parsed['request_method'],
                    path=parsed['request_url'],
                    status=int(parsed['status']),
                    bytes_sent=int(parsed['response_bytes_clf']) if parsed['response_bytes_clf'] != '-' else 0,
                    referer=parsed['request_header_referer'],
                    user_agent=parsed['request_header_user_agent'],
                    processed_at=datetime.utcnow().isoformat()
                )
                
                # Enrich with additional data
                log_entry = self.security_analyzer.analyze(log_entry)
                log_entry = self.geo_enricher.enrich(log_entry)
                
                # Cache the result
                if len(self.cache) >= self.cache_size:
                    # Remove oldest entry
                    oldest_key = next(iter(self.cache))
                    del self.cache[oldest_key]
                
                self.cache[line_hash] = log_entry
                LOGS_PROCESSED.inc()
                
                return log_entry
                
        except Exception as e:
            LOGS_FAILED.inc()
            logger.error("Failed to parse log line", line=line, error=str(e))
            return None

class HealthChecker:
    """Health check for services."""
    
    def __init__(self, config: Dict):
        self.config = config
        self.redis_client = None
        self._init_redis()
    
    def _init_redis(self):
        """Initialize Redis client for health checks."""
        try:
            redis_config = self.config.get('redis', {})
            if redis_config:
                self.redis_client = redis.Redis(
                    host=redis_config.get('host', 'localhost'),
                    port=redis_config.get('port', 6379),
                    db=redis_config.get('db', 0)
                )
        except Exception as e:
            logger.error("Failed to initialize Redis", error=str(e))
    
    def check_kafka(self) -> bool:
        """Check Kafka health."""
        try:
            from kafka import KafkaAdminClient
            admin_client = KafkaAdminClient(
                bootstrap_servers=self.config['kafka']['bootstrap_servers']
            )
            admin_client.close()
            return True
        except Exception as e:
            logger.error("Kafka health check failed", error=str(e))
            return False
    
    def check_elasticsearch(self) -> bool:
        """Check Elasticsearch health."""
        try:
            es = Elasticsearch([self.config['elasticsearch']['host']])
            return es.ping()
        except Exception as e:
            logger.error("Elasticsearch health check failed", error=str(e))
            return False
    
    def check_redis(self) -> bool:
        """Check Redis health."""
        if not self.redis_client:
            return True  # Skip if not configured
        try:
            self.redis_client.ping()
            return True
        except Exception as e:
            logger.error("Redis health check failed", error=str(e))
            return False
    
    def get_health_status(self) -> Dict:
        """Get overall health status."""
        return {
            'kafka': self.check_kafka(),
            'elasticsearch': self.check_elasticsearch(),
            'redis': self.check_redis(),
            'memory_usage': psutil.Process().memory_info().rss / 1024 / 1024,  # MB
            'cpu_percent': psutil.Process().cpu_percent(),
            'timestamp': datetime.utcnow().isoformat()
        }

class LogProducer:
    """Enhanced Kafka producer with retries and monitoring."""
    
    def __init__(self, config_path: str = 'config/config.yml'):
        with open(config_path, 'r') as f:
            self.config = yaml.safe_load(f)
        
        self.producer = KafkaProducer(
            bootstrap_servers=self.config['kafka']['bootstrap_servers'],
            value_serializer=lambda x: json.dumps(x).encode('utf-8'),
            retries=3,
            retry_backoff_ms=100,
            batch_size=16384,
            linger_ms=10,
            compression_type='snappy'
        )
        self.topic = self.config['kafka']['topic']
        self.circuit_breaker = CircuitBreaker()
        self.health_checker = HealthChecker(self.config)
    
    def send_log(self, log_data: Dict, retries: int = 3) -> bool:
        """Send a log entry to Kafka with circuit breaker and retries."""
        for attempt in range(retries):
            try:
                with self.circuit_breaker.call():
                    future = self.producer.send(self.topic, value=log_data)
                    future.get(timeout=5)
                    logger.debug("Sent log entry", path=log_data.get('path', 'N/A'))
                    return True
            except Exception as e:
                logger.warning(
                    "Failed to send log entry",
                    attempt=attempt + 1,
                    error=str(e),
                    path=log_data.get('path', 'N/A')
                )
                if attempt < retries - 1:
                    time.sleep(0.1 * (2 ** attempt))  # Exponential backoff
        
        logger.error("Failed to send log entry after retries", path=log_data.get('path', 'N/A'))
        return False
    
    def send_batch(self, log_entries: List[Dict]) -> int:
        """Send multiple log entries efficiently."""
        successful = 0
        for log_entry in log_entries:
            if self.send_log(log_entry):
                successful += 1
        return successful
    
    def close(self):
        """Close the Kafka producer."""
        self.producer.flush()
        self.producer.close()

class ElasticsearchHandler:
    """Enhanced Elasticsearch handler with bulk operations and monitoring."""
    
    def __init__(self, config_path: str = 'config/config.yml'):
        with open(config_path, 'r') as f:
            self.config = yaml.safe_load(f)
        
        self.es = Elasticsearch(
            [self.config['elasticsearch']['host']],
            retry_on_timeout=True,
            max_retries=3,
            timeout=30
        )
        self.index = self.config['elasticsearch']['index']
        self.bulk_buffer = []
        self.bulk_size = self.config['elasticsearch'].get('bulk_size', 100)
        self.circuit_breaker = CircuitBreaker()
        
        # Create index if it doesn't exist
        if not self.es.indices.exists(index=self.index):
            self.create_index()
    
    def create_index(self):
        """Create the Elasticsearch index with optimized mapping."""
        mapping = {
            "settings": {
                "number_of_shards": 1,
                "number_of_replicas": 0,
                "refresh_interval": "30s",
                "index.codec": "best_compression"
            },
            "mappings": {
                "properties": {
                    "timestamp": {"type": "date"},
                    "ip_address": {"type": "ip"},
                    "method": {"type": "keyword"},
                    "path": {"type": "keyword"},
                    "status": {"type": "integer"},
                    "bytes_sent": {"type": "long"},
                    "referer": {"type": "keyword"},
                    "user_agent": {"type": "text", "analyzer": "standard"},
                    "processed_at": {"type": "date"},
                    "geo_country": {"type": "keyword"},
                    "geo_city": {"type": "keyword"},
                    "is_bot": {"type": "boolean"},
                    "security_threat": {"type": "boolean"},
                    "response_time": {"type": "float"}
                }
            }
        }
        
        try:
            self.es.indices.create(index=self.index, body=mapping)
            logger.info("Created Elasticsearch index", index=self.index)
        except Exception as e:
            logger.error("Failed to create Elasticsearch index", error=str(e))
    
    def store_log(self, log_data: Dict):
        """Store a log entry with buffering for bulk operations."""
        self.bulk_buffer.append({
            "_index": self.index,
            "_source": log_data
        })
        
        if len(self.bulk_buffer) >= self.bulk_size:
            self.flush_bulk()
    
    def flush_bulk(self):
        """Flush buffered logs to Elasticsearch."""
        if not self.bulk_buffer:
            return
        
        try:
            with self.circuit_breaker.call():
                response = self.es.bulk(body=self.bulk_buffer)
                
                # Check for errors
                if response.get('errors'):
                    error_count = sum(1 for item in response['items'] if 'error' in item.get('index', {}))
                    ELASTICSEARCH_ERRORS.inc(error_count)
                    logger.error("Bulk indexing errors", error_count=error_count)
                
                logger.info("Bulk indexed logs", count=len(self.bulk_buffer))
                self.bulk_buffer.clear()
                
        except Exception as e:
            ELASTICSEARCH_ERRORS.inc()
            logger.error("Failed to bulk index logs", error=str(e))
            # Keep buffer for retry
    
    def create_dashboard(self):
        """Create a basic Kibana dashboard."""
        # This would typically be done through Kibana API
        # Here's a placeholder for dashboard creation
        pass

class LogConsumer:
    """Enhanced Kafka consumer with parallel processing and monitoring."""
    
    def __init__(self, config_path: str = 'config/config.yml'):
        with open(config_path, 'r') as f:
            self.config = yaml.safe_load(f)
        
        self.consumer = KafkaConsumer(
            self.config['kafka']['topic'],
            bootstrap_servers=self.config['kafka']['bootstrap_servers'],
            value_deserializer=lambda x: json.loads(x.decode('utf-8')),
            group_id='log_processor_group',
            auto_offset_reset='latest',
            enable_auto_commit=False,
            max_poll_records=100
        )
        
        self.es_handler = ElasticsearchHandler(config_path)
        self.running = False
        self.thread_pool = ThreadPoolExecutor(max_workers=4)
        self.health_checker = HealthChecker(self.config)
    
    def process_batch(self, messages: List) -> int:
        """Process a batch of messages in parallel."""
        futures = []
        for message in messages:
            future = self.thread_pool.submit(self._process_single_message, message)
            futures.append(future)
        
        successful = 0
        for future in as_completed(futures):
            try:
                if future.result():
                    successful += 1
            except Exception as e:
                logger.error("Failed to process message", error=str(e))
        
        return successful
    
    def _process_single_message(self, message) -> bool:
        """Process a single message."""
        try:
            log_data = message.value
            self.es_handler.store_log(log_data)
            return True
        except Exception as e:
            logger.error("Failed to process message", error=str(e))
            return False
    
    def process_logs(self):
        """Continuously process incoming logs with batch processing."""
        self.running = True
        logger.info("Starting log consumer")
        
        try:
            while self.running:
                # Poll for messages
                message_batch = self.consumer.poll(timeout_ms=1000)
                
                if message_batch:
                    all_messages = []
                    for tp, messages in message_batch.items():
                        all_messages.extend(messages)
                    
                    # Process batch
                    successful = self.process_batch(all_messages)
                    
                    # Commit offsets
                    try:
                        self.consumer.commit()
                        logger.debug("Committed offsets", processed=successful)
                    except Exception as e:
                        logger.error("Failed to commit offsets", error=str(e))
                
                # Flush any remaining bulk operations
                self.es_handler.flush_bulk()
                
                # Update metrics
                ACTIVE_CONNECTIONS.set(len(self.consumer.assignment()))
                
        except KeyboardInterrupt:
            logger.info("Shutting down consumer...")
        finally:
            self.cleanup()
    
    def cleanup(self):
        """Clean up resources."""
        self.running = False
        self.es_handler.flush_bulk()
        self.thread_pool.shutdown(wait=True)
        self.consumer.close()

class LogPipeline:
    """Main pipeline orchestrator."""
    
    def __init__(self, config_path: str = 'config/config.yml'):
        self.config_path = config_path
        self.config = self._load_config()
        self.components = {}
        self.running = False
        self.health_checker = HealthChecker(self.config)
        
        # Setup signal handlers
        signal.signal(signal.SIGINT, self._signal_handler)
        signal.signal(signal.SIGTERM, self._signal_handler)
    
    def _load_config(self) -> Dict:
        """Load configuration with validation."""
        if not os.path.exists(self.config_path):
            self.config_path = self.create_default_config()
        
        with open(self.config_path, 'r') as f:
            config = yaml.safe_load(f)
        
        # Validate required fields
        required_fields = ['kafka', 'elasticsearch']
        for field in required_fields:
            if field not in config:
                raise ValueError(f"Missing required config field: {field}")
        
        return config
    
    def _signal_handler(self, signum, frame):
        """Handle shutdown signals."""
        logger.info("Received shutdown signal", signal=signum)
        self.shutdown()
    
    def initialize(self):
        """Initialize all components."""
        logger.info("Initializing log pipeline")
        
        # Start metrics server
        metrics_port = self.config.get('monitoring', {}).get('metrics_port', 8000)
        start_http_server(metrics_port)
        logger.info("Started metrics server", port=metrics_port)
        
        # Initialize components
        self.components['parser'] = LogParser()
        self.components['producer'] = LogProducer(self.config_path)
        self.components['consumer'] = LogConsumer(self.config_path)
        
        logger.info("Pipeline initialized successfully")
    
    def start(self):
        """Start the pipeline."""
        self.initialize()
        self.running = True
        
        # Start consumer in a separate thread
        consumer_thread = threading.Thread(
            target=self.components['consumer'].process_logs
        )
        consumer_thread.daemon = True
        consumer_thread.start()
        
        # Health check loop
        while self.running:
            health_status = self.health_checker.get_health_status()
            logger.info("Health check", **health_status)
            
            if not all(health_status[key] for key in ['kafka', 'elasticsearch']):
                logger.warning("Some services are unhealthy")
            
            time.sleep(30)  # Health check interval
    
    def process_log_file(self, file_path: str):
        """Process a log file."""
        parser = self.components['parser']
        producer = self.components['producer']
        
        logger.info("Processing log file", file_path=file_path)
        
        processed = 0
        failed = 0
        
        try:
            with open(file_path, 'r') as f:
                for line_num, line in enumerate(f, 1):
                    line = line.strip()
                    if not line:
                        continue
                    
                    log_entry = parser.parse_log_line(line)
                    if log_entry:
                        if producer.send_log(log_entry.to_dict()):
                            processed += 1
                        else:
                            failed += 1
                    else:
                        failed += 1
                    
                    if line_num % 1000 == 0:
                        logger.info(
                            "Processing progress",
                            processed=processed,
                            failed=failed,
                            line_num=line_num
                        )
        
        except Exception as e:
            logger.error("Failed to process log file", file_path=file_path, error=str(e))
        
        logger.info(
            "Finished processing log file",
            file_path=file_path,
            processed=processed,
            failed=failed
        )
    
    def shutdown(self):
        """Shutdown the pipeline gracefully."""
        logger.info("Shutting down pipeline")
        self.running = False
        
        # Close components
        for name, component in self.components.items():
            if hasattr(component, 'close'):
                component.close()
        
        logger.info("Pipeline shutdown complete")
    
    def create_default_config(self) -> str:
        """Create default configuration file with enhanced settings."""
        config = {
            'kafka': {
                'bootstrap_servers': ['localhost:9092'],
                'topic': 'web_logs'
            },
            'elasticsearch': {
                'host': 'http://localhost:9200',
                'index': 'web_logs',
                'bulk_size': 100
            },
            'redis': {
                'host': 'localhost',
                'port': 6379,
                'db': 0
            },
            'monitoring': {
                'alert_threshold': 100,
                'window_seconds': 300,
                'metrics_port': 8000
            },
            'security': {
                'enable_geo_enrichment': True,
                'enable_threat_detection': True
            },
            'performance': {
                'max_workers': 4,
                'batch_size': 100,
                'rate_limit': 1000
            }
        }
        
        config_dir = Path("config")
        config_dir.mkdir(exist_ok=True)
        
        config_path = config_dir / "config.yml"
        with open(config_path, 'w') as f:
            yaml.dump(config, f, default_flow_style=False)
        
        return str(config_path)

# CLI interface
def main():
    """Main entry point with CLI interface."""
    import argparse
    
    parser = argparse.ArgumentParser(description='Enhanced Log Processing Pipeline')
    parser.add_argument('--config', default='config/config.yml', help='Config file path')
    parser.add_argument('--file', help='Process a specific log file')
    parser.add_argument('--daemon', action='store_true', help='Run as daemon')
    
    args = parser.parse_args()
    
    # Initialize pipeline
    pipeline = LogPipeline(args.config)
    
    try:
        if args.file:
            # Process single file
            pipeline.initialize()
            pipeline.process_log_file(args.file)
        elif args.daemon:
            # Run as daemon
            pipeline.start()
        else:
            # Interactive mode
            pipeline.initialize()
            
            # Example usage
            sample_log = '127.0.0.1 - - [10/Oct/2023:13:55:36 +0000] "GET /api/users HTTP/1.1" 200 1234 "http://example.com" "Mozilla/5.0"'
            parsed_log = pipeline.components['parser'].parse_log_line(sample_log)
            
            if parsed_log:
                pipeline.components['producer'].send_log(parsed_log.to_dict())
                logger.info("Sent sample log", log_data=parsed_log.to_dict())
            
            # Start consuming
            pipeline.components['consumer'].process_logs()
            
    except KeyboardInterrupt:
        logger.info("Interrupted by user")
    finally:
        pipeline.shutdown()

if __name__ == "__main__":
    main()