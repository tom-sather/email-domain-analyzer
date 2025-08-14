# Swiss Army Domain Tool

A comprehensive email domain analysis tool that combines MX lookup, DNS validation, website accessibility checks, and domain categorization into a single high-performance solution.

## 🚀 Features

- **Email Domain Validation** - Checks MX, A, SPF, and DMARC records
- **Website Accessibility** - Validates domain liveness and detects parking pages
- **Provider Categorization** - Identifies Google, Microsoft, Yahoo, and other email providers
- **Disposable Email Detection** - Flags temporary/disposable email services
- **High Performance** - Async processing with connection pooling and caching
- **Database Storage** - SQLite database for persistent caching
- **Batch Processing** - Efficient handling of large email lists
- **Comprehensive Logging** - Detailed progress tracking and error reporting

## 📋 Requirements

- Python 3.7+
- Required packages (install via `pip install -r requirements.txt`):
  - `aiohttp`
  - `aiodns`
  - `aiosqlite`
  - `beautifulsoup4`
  - `dnspython`

## 🛠️ Installation

1. **Clone or download the script:**
   ```bash
   git clone <repository-url>
   cd NewMXTool
   ```

2. **Install dependencies:**
   ```bash
   pip install aiohttp aiodns aiosqlite beautifulsoup4 dnspython
   ```

3. **Make the script executable:**
   ```bash
   chmod +x swissarmydomain.py
   ```

## 📖 Usage

### Basic Usage

```bash
# Process a text file with one email/domain per line
python3 swissarmydomain.py input.txt

# Process a CSV file
python3 swissarmydomain.py input.csv csv
```

### Input File Formats

**Text file (`input.txt`):**
```
test@example.com
admin@google.com
info@microsoft.com
domain.com
```

**CSV file (`input.csv`):**
```csv
email,other_column
test@example.com,some_data
admin@google.com,more_data
info@microsoft.com,extra_data
```

### Output

The script generates a CSV file with the following columns:

| Column | Description |
|--------|-------------|
| `ENTRY` | Original input (email or domain) |
| `DOMAIN` | Extracted domain |
| `STATUS` | Valid/Invalid/Risky |
| `REASON` | Explanation for the status |
| `MX_AVAILABLE` | Yes/No |
| `MX_PROVIDER` | Google/Microsoft/Yahoo/etc. |
| `A_AVAILABLE` | Yes/No |
| `SPF_AVAILABLE` | Yes/No |
| `DMARC_AVAILABLE` | Yes/No |
| `SITE_LIVE` | Yes/No |
| `PARKED` | Yes/No |
| `DISPOSABLE` | Yes/No |

## ⚙️ Configuration

The script includes several configurable parameters:

```python
# Performance settings
BATCH_SIZE = 200              # Domains processed per batch
MAX_CONCURRENT = 100          # Concurrent connections
QUERY_TIMEOUT = 60           # DNS query timeout (seconds)
CONN_TIMEOUT = 3             # HTTP connection timeout (seconds)

# Cache settings
DOMAIN_CACHE_TTL = 86400     # DNS cache TTL (24 hours)
WEBSITE_CACHE_TTL = 3600     # Website cache TTL (1 hour)
```

## 🗄️ Database

The script uses SQLite for caching and performance:

- **Location**: `.cache/domain_checks.db`
- **Tables**: `domain_checks`, `website_checks`, `results_history`
- **Benefits**: Faster subsequent runs, reduced API calls, persistent storage

## 🔍 Email Provider Detection

The tool categorizes domains into major email providers:

- **Google**: Gmail, Google Apps, Google Workspace
- **Microsoft**: Outlook, Hotmail, Office 365
- **Yahoo**: Yahoo Mail, AOL
- **Apple**: iCloud, Mac.com
- **Other**: Custom domains, business email providers

## 🚫 Disposable Email Detection

Automatically flags temporary/disposable email services:

- Mailinator, Yopmail, 10MinuteMail
- Temporary mail services
- Fake email generators
- Disposable domain providers

## 📊 Performance Features

- **Async Processing**: Concurrent DNS and HTTP requests
- **Connection Pooling**: Efficient HTTP connections
- **LRU Caching**: Memory-efficient caching with TTL
- **Batch Processing**: Processes multiple domains simultaneously
- **Database Caching**: Persistent storage for repeated checks

## 📝 Logging

The script provides detailed logging:

- **File**: `domain_analyzer.log`
- **Console**: Real-time progress updates
- **Levels**: INFO, WARNING, ERROR
- **Details**: Processing progress, errors, cache hits/misses

## 🔧 Error Handling

- **Retry Logic**: Automatic retries for failed DNS queries
- **Timeout Protection**: Prevents hanging on unresponsive domains
- **Graceful Degradation**: Continues processing even if some domains fail
- **Input Validation**: Handles malformed emails and domains

## 📈 Example Output

```csv
ENTRY,DOMAIN,STATUS,REASON,MX_AVAILABLE,MX_PROVIDER,A_AVAILABLE,SPF_AVAILABLE,DMARC_AVAILABLE,SITE_LIVE,PARKED,DISPOSABLE
test@example.com,example.com,Valid,Domain passed all checks,Yes,Other,Yes,Yes,Yes,Yes,No,No
admin@google.com,google.com,Valid,Domain passed all checks,Yes,Google,Yes,Yes,Yes,Yes,No,No
user@mailinator.com,mailinator.com,Invalid,Disposable email provider detected,Yes,Other,Yes,No,No,Yes,No,Yes
```

## 🚨 Troubleshooting

### Common Issues

1. **"Command not found: python"**
   - Use `python3` instead of `python`

2. **Missing dependencies**
   - Install required packages: `pip install aiohttp aiodns aiosqlite beautifulsoup4 dnspython`

3. **Permission denied**
   - Make script executable: `chmod +x swissarmydomain.py`

4. **Large files take too long**
   - The script processes in batches, large files will take time
   - Results are cached for faster subsequent runs

### Performance Tips

- **First run**: May take longer as it builds the cache
- **Subsequent runs**: Much faster due to database caching
- **Large datasets**: Consider processing in smaller chunks
- **Network issues**: Script includes retry logic and timeouts

## 🔄 Updates and Maintenance

The script automatically:
- **Updates cache**: Based on TTL settings
- **Handles errors**: Graceful degradation and retries
- **Manages memory**: LRU cache prevents memory leaks
- **Cleans up**: Proper resource cleanup on exit

## 📄 License

This tool is provided as-is for educational and practical use.

## 🤝 Contributing

Feel free to submit issues, feature requests, or improvements!

---

**Note**: This tool is designed for legitimate email validation and domain analysis. Please use responsibly and in accordance with applicable laws and terms of service.
