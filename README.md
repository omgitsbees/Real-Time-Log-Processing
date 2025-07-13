# Enhanced Log Processing Pipeline

A production-ready, scalable log processing pipeline built with Python that ingests Apache access logs, processes them through Kafka, and stores them in Elasticsearch with advanced monitoring, security analysis, and performance optimizations.

## Features

### Core Functionality
- **Apache Log Parsing**: Processes standard Apache access log format with structured output
- **Kafka Integration**: Reliable message queuing with producer/consumer patterns
- **Elasticsearch Storage**: Optimized indexing with bulk operations and custom mappings
- **Real-time Processing**: Continuous log processing with configurable batch sizes

### Production Features
- **Monitoring & Metrics**: Prometheus metrics integration with health checks
- **Security Analysis**: Built-in threat detection and bot identification
- **GeoIP Enrichment**: Automatic location data enrichment for IP addresses
- **Circuit Breaker**: Fault tolerance for external service calls
- **Rate Limiting**: Configurable rate limiting to prevent system overload
- **Structured Logging**: JSON-formatted logs with structured metadata

### Performance Optimizations
- **Bulk Operations**: Efficient batch processing for Elasticsearch
- **Caching**: In-memory caching for parsed log entries
- **Parallel Processing**: Multi-threaded message processing
- **Connection Pooling**: Optimized database and service connections

## Architecture

```
Log Files → Parser → Kafka Producer → Kafka Topic → Kafka Consumer → Elasticsearch
                                                  ↓
                                              Monitoring
                                              Security Analysis
                                              GeoIP Enrichment
```

## Installation

### Prerequisites
- Python 3.8+
- Apache Kafka
- Elasticsearch
- Redis (optional, for caching)

### Dependencies
```bash
pip install -r requirements.txt
```

Required packages:
```
apache-log-parser
pyyaml
kafka-python
elasticsearch
redis
geoip2
prometheus-client
structlog
psutil
aiohttp
```

### Optional Dependencies
- **GeoIP Database**: Download GeoLite2-City.mmdb from MaxMind for location enrichment
- **Redis**: For advanced caching and session management

## Configuration

The pipeline uses a YAML configuration file. A default configuration is created automatically on first run at `config/config.yml`.

### Example Configuration
```yaml
kafka:
  bootstrap_servers: ['localhost:9092']
  topic: 'web_logs'

elasticsearch:
  host: 'http://localhost:9200'
  index: 'web_logs'
  bulk_size: 100

redis:
  host: 'localhost'
  port: 6379
  db: 0

monitoring:
  alert_threshold: 100
  window_seconds: 300
  metrics_port: 8000

security:
  enable_geo_enrichment: true
  enable_threat_detection: true

performance:
  max_workers: 4
  batch_size: 100
  rate_limit: 1000
```

## Usage

### Command Line Interface

#### Process a Single Log File
```bash
python enhanced_pipeline.py --file /path/to/access.log
```

#### Run as Daemon
```bash
python enhanced_pipeline.py --daemon
```

#### Custom Configuration
```bash
python enhanced_pipeline.py --config /path/to/custom_config.yml
```

### Programmatic Usage

```python
from enhanced_pipeline import LogPipeline

# Initialize pipeline
pipeline = LogPipeline('config/config.yml')

# Process a log file
pipeline.process_log_file('/path/to/access.log')

# Start continuous processing
pipeline.start()
```

## Monitoring

### Prometheus Metrics
The pipeline exposes Prometheus metrics on port 8000 (configurable):

- `logs_processed_total`: Total number of logs processed
- `logs_failed_total`: Total number of failed log processing attempts
- `log_processing_seconds`: Histogram of log processing times
- `active_connections`: Number of active Kafka connections
- `kafka_consumer_lag`: Kafka consumer lag metric
- `elasticsearch_errors_total`: Total Elasticsearch errors

### Health Checks
Health status is logged every 30 seconds and includes:
- Kafka connectivity
- Elasticsearch connectivity
- Redis connectivity (if configured)
- Memory usage
- CPU usage

### Structured Logging
All logs are output in JSON format with structured metadata:
```json
{
  "timestamp": "2023-10-10T13:55:36Z",
  "level": "info",
  "logger": "enhanced_pipeline",
  "message": "Processed log entry",
  "path": "/api/users",
  "status": 200,
  "processing_time": 0.005
}
```

## Security Features

### Threat Detection
Automatically detects common security threats:
- Directory traversal attempts (`../`)
- XSS attempts (`<script>`)
- SQL injection patterns (`union select`)
- File inclusion attempts (`etc/passwd`)
- Command injection (`cmd.exe`)

### Bot Detection
Identifies bot traffic using pattern matching:
- Common bot user agents
- Search engine crawlers
- Social media bots

### Rate Limiting
Configurable rate limiting prevents system overload:
- Maximum requests per time window
- Automatic request dropping when limits exceeded
- Monitoring of rate limit hits

## Data Enrichment

### GeoIP Location
Automatically enriches log entries with geographic information:
- Country identification
- City identification
- Requires GeoLite2-City.mmdb database

### Structured Data
Log entries are parsed into structured format:
```json
{
  "timestamp": "2023-10-10T13:55:36Z",
  "ip_address": "127.0.0.1",
  "method": "GET",
  "path": "/api/users",
  "status": 200,
  "bytes_sent": 1234,
  "referer": "http://example.com",
  "user_agent": "Mozilla/5.0...",
  "geo_country": "United States",
  "geo_city": "New York",
  "is_bot": false,
  "security_threat": false,
  "processed_at": "2023-10-10T13:55:40Z"
}
```

## Performance Tuning

### Elasticsearch Optimization
- Bulk indexing for improved throughput
- Compressed storage with `best_compression` codec
- Optimized field mappings
- Configurable refresh intervals

### Kafka Configuration
- Batch processing for improved efficiency
- Compression with Snappy algorithm
- Configurable retry policies
- Auto-commit disabled for better control

### Memory Management
- LRU caching for parsed entries
- Configurable cache sizes
- Automatic memory monitoring

## Error Handling

### Circuit Breaker Pattern
Prevents cascading failures:
- Configurable failure thresholds
- Automatic recovery attempts
- Half-open state for testing recovery

### Retry Logic
Automatic retry with exponential backoff:
- Configurable retry attempts
- Exponential backoff delays
- Dead letter queue support

### Graceful Degradation
System continues operating with reduced functionality:
- Skip GeoIP enrichment if database unavailable
- Continue processing without Redis if not configured
- Fallback to individual operations if bulk operations fail

## Development

### Running Tests
```bash
pytest tests/
```

### Code Quality
```bash
# Linting
flake8 enhanced_pipeline.py

# Type checking
mypy enhanced_pipeline.py

# Security scanning
bandit enhanced_pipeline.py
```

### Contributing
1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Add tests for new functionality
5. Submit a pull request

## Deployment

### Docker
```dockerfile
FROM python:3.9-slim

WORKDIR /app
COPY requirements.txt .
RUN pip install -r requirements.txt

COPY . .
CMD ["python", "enhanced_pipeline.py", "--daemon"]
```

### Kubernetes
Example deployment configuration available in `k8s/` directory.

### Systemd Service
```ini
[Unit]
Description=Log Processing Pipeline
After=network.target

[Service]
Type=simple
User=logprocessor
WorkingDirectory=/opt/log-pipeline
ExecStart=/usr/bin/python3 enhanced_pipeline.py --daemon
Restart=always
RestartSec=10

[Install]
WantedBy=multi-user.target
```

## Differences from Original Implementation

This enhanced version provides significant improvements over the original code in the following areas:

### Production Readiness
**Original**: Basic prototype with minimal error handling
**Enhanced**: 
- Complete error handling with try/catch blocks throughout
- Graceful shutdown with signal handlers
- Resource cleanup and connection management
- Production-ready logging with structured output

### Monitoring and Observability
**Original**: Basic console logging only
**Enhanced**:
- Prometheus metrics integration for monitoring
- Health check endpoints for load balancers
- Structured JSON logging with metadata
- Performance metrics (CPU, memory, processing time)
- Kafka lag monitoring

### Reliability and Fault Tolerance
**Original**: No retry logic or fault tolerance
**Enhanced**:
- Circuit breaker pattern for external service calls
- Retry logic with exponential backoff
- Rate limiting to prevent system overload
- Bulk operations with fallback to individual operations
- Dead letter queue support for failed messages

### Security Features
**Original**: No security analysis
**Enhanced**:
- Built-in threat detection (XSS, SQL injection, directory traversal)
- Bot detection with pattern matching
- Security threat flagging in log entries
- Rate limiting for DDoS protection

### Performance Optimizations
**Original**: Sequential processing with basic operations
**Enhanced**:
- Parallel processing with ThreadPoolExecutor
- Bulk Elasticsearch operations for better throughput
- In-memory caching for parsed log entries
- Optimized Elasticsearch mappings with compression
- Batch processing for Kafka messages

### Data Enrichment
**Original**: Basic log parsing only
**Enhanced**:
- GeoIP enrichment for location data
- Structured data validation using dataclasses
- Bot and threat detection metadata
- Response time calculation
- Enhanced field parsing with validation

### Configuration Management
**Original**: Hardcoded configuration values
**Enhanced**:
- Comprehensive YAML configuration system
- Configuration validation with required field checks
- Environment-specific configuration support
- Default configuration auto-generation

### CLI and Operational Features
**Original**: No CLI interface
**Enhanced**:
- Full CLI interface with multiple operation modes
- File processing mode for batch operations
- Daemon mode for continuous processing
- Configuration file specification
- Proper argument parsing and validation

### Code Organization
**Original**: Monolithic structure
**Enhanced**:
- Modular design with separate classes for each component
- Dependency injection for better testability
- Clear separation of concerns
- Comprehensive documentation and type hints

### Error Recovery
**Original**: Basic exception handling
**Enhanced**:
- Comprehensive error recovery strategies
- Circuit breaker for cascading failure prevention
- Automatic retry with backoff
- Graceful degradation when services are unavailable

### Scalability
**Original**: Single-threaded processing
**Enhanced**:
- Multi-threaded message processing
- Configurable worker pools
- Bulk operations for improved throughput
- Connection pooling for database connections

This enhanced version transforms a basic prototype into a production-ready, enterprise-grade log processing system suitable for high-volume environments with comprehensive monitoring, security, and operational features.
