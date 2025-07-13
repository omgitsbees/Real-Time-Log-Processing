import apache_log_parser
import json
from datetime import datetime
import logging
from pathlib import Path
import yaml
from kafka import KafkaProducer, KafkaConsumer
from elasticsearch import Elasticsearch
import time

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class LogParser:
    def __init__(self):
        self.line_parser = apache_log_parser.make_parser(
            "%h %l %u %t \"%r\" %>s %b \"%{Referer}i\" \"%{User-Agent}i\""
        )
    
    def parse_log_line(self, line: str) -> dict:
        """Parse a single log line into a structured format."""
        try:
            parsed = self.line_parser(line)
            return {
                'timestamp': parsed['time_received_utc_isoformat'],
                'ip_address': parsed['remote_host'],
                'method': parsed['request_method'],
                'path': parsed['request_url'],
                'status': int(parsed['status']),
                'bytes_sent': parsed['response_bytes_clf'],
                'referer': parsed['request_header_referer'],
                'user_agent': parsed['request_header_user_agent'],
                'processed_at': datetime.utcnow().isoformat()
            }
        except Exception as e:
            return {
                'error': str(e),
                'raw_line': line,
                'processed_at': datetime.utcnow().isoformat()
            }

class LogProducer:
    def __init__(self, config_path: str = 'config/config.yml'):
        with open(config_path, 'r') as f:
            config = yaml.safe_load(f)
        
        self.producer = KafkaProducer(
            bootstrap_servers=config['kafka']['bootstrap_servers'],
            value_serializer=lambda x: json.dumps(x).encode('utf-8')
        )
        self.topic = config['kafka']['topic']
    
    def send_log(self, log_data: dict):
        """Send a log entry to Kafka."""
        try:
            future = self.producer.send(self.topic, value=log_data)
            future.get(timeout=2)  # Wait for confirmation
            logger.info(f"Sent log entry: {log_data.get('path', 'N/A')}")
        except Exception as e:
            logger.error(f"Error sending log entry: {str(e)}")
    
    def close(self):
        """Close the Kafka producer."""
        self.producer.close()

class ElasticsearchHandler:
    def __init__(self, config_path: str = 'config/config.yml'):
        with open(config_path, 'r') as f:
            config = yaml.safe_load(f)
        
        self.es = Elasticsearch([config['elasticsearch']['host']])
        self.index = config['elasticsearch']['index']
        
        # Create index if it doesn't exist
        if not self.es.indices.exists(index=self.index):
            self.create_index()
    
    def create_index(self):
        """Create the Elasticsearch index with mapping."""
        mapping = {
            "mappings": {
                "properties": {
                    "timestamp": {"type": "date"},
                    "ip_address": {"type": "ip"},
                    "method": {"type": "keyword"},
                    "path": {"type": "keyword"},
                    "status": {"type": "integer"},
                    "bytes_sent": {"type": "long"},
                    "referer": {"type": "keyword"},
                    "user_agent": {"type": "text"},
                    "processed_at": {"type": "date"}
                }
            }
        }
        self.es.indices.create(index=self.index, body=mapping)
        logger.info(f"Created index: {self.index}")
    
    def store_log(self, log_data: dict):
        """Store a log entry in Elasticsearch."""
        try:
            self.es.index(index=self.index, body=log_data)
            logger.info(f"Stored log entry for: {log_data.get('path', 'N/A')}")
        except Exception as e:
            logger.error(f"Error storing log entry: {str(e)}")

class LogConsumer:
    def __init__(self, config_path: str = 'config/config.yml'):
        with open(config_path, 'r') as f:
            config = yaml.safe_load(f)
        
        self.consumer = KafkaConsumer(
            config['kafka']['topic'],
            bootstrap_servers=config['kafka']['bootstrap_servers'],
            value_deserializer=lambda x: json.loads(x.decode('utf-8')),
            group_id='log_processor_group',
            auto_offset_reset='latest'
        )
        
        self.es_handler = ElasticsearchHandler(config_path)
    
    def process_logs(self):
        """Continuously process incoming logs."""
        try:
            for message in self.consumer:
                log_data = message.value
                self.es_handler.store_log(log_data)
        except KeyboardInterrupt:
            logger.info("Shutting down consumer...")
        finally:
            self.consumer.close()

def create_default_config():
    """Create default configuration file."""
    config = {
        'kafka': {
            'bootstrap_servers': ['localhost:9092'],
            'topic': 'web_logs'
        },
        'elasticsearch': {
            'host': 'http://localhost:9200',
            'index': 'web_logs'
        },
        'monitoring': {
            'alert_threshold': 100,
            'window_seconds': 300
        }
    }
    
    config_dir = Path("config")
    config_dir.mkdir(exist_ok=True)
    
    config_path = config_dir / "config.yml"
    with open(config_path, 'w') as f:
        yaml.dump(config, f)
    
    return config_path

if __name__ == "__main__":
    # Ensure config exists
    config_path = create_default_config()
    
    # Initialize components
    parser = LogParser()
    producer = LogProducer(str(config_path))
    consumer = LogConsumer(str(config_path))
    
    # Example usage
    sample_log = '127.0.0.1 - - [10/Oct/2023:13:55:36 +0000] "GET /api/users HTTP/1.1" 200 1234 "http://example.com" "Mozilla/5.0"'
    parsed_log = parser.parse_log_line(sample_log)
    producer.send_log(parsed_log)
    
    # Start consuming logs
    try:
        consumer.process_logs()
    except KeyboardInterrupt:
        logger.info("Shutting down pipeline...")
        producer.close()