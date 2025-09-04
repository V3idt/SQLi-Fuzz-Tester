# Simple SQLi Fuzz Tester

This is a Python-based SQL injection fuzzer that can be used to test web applications for SQL injection vulnerabilities. The fuzzer works by sending a variety of SQL injection payloads to a target URL and analyzing the responses to determine if a vulnerability is present.

For testing it is recommended that you use https://github.com/V3idt/SQLi-Vulnerable-App.git

## Prerequisites

- Python 3.6+

## Installation

1. Clone the repository:
   ```bash
   git clone https://github.com/your-username/SQLi-Fuzzer.git
   ```
2. Install the required dependencies:
   ```bash
   pip install -r requirments.txt
   ```

## Usage

To use the fuzzer, simply run the `main.py` script with the target URL as an argument:

```bash
python main.py [options] <url>
```

### Options

- `--delay`: The delay between requests in seconds (default: 1).
- `--verbose`: Enable verbose output.
- `--output`: The output file for the report in JSON format.
- `--payloads`: A custom payloads JSON file.

### Example

```bash
python main.py --verbose --output report.json https://example.com
```

## Disclaimer

This tool is for educational purposes only. Do not use it to attack any system that you do not have permission to test. The author is not responsible for any damage caused by this tool.

## Payloads

The fuzzer uses a variety of SQL injection payloads, which are located in the `payloads` variable in `main.py`. You can also specify a custom payloads file using the `--payloads` option.

## Reporting

The fuzzer will generate a report in JSON format if a vulnerability is found. The report will contain the following information:

- `url`: The URL where the vulnerability was found.
- `parameter`: The parameter that is vulnerable.
- `payload`: The payload that was used to trigger the vulnerability.
- `type`: The type of SQL injection vulnerability.
- `original_value`: The original value of the parameter.
- `evidence`: The evidence of the vulnerability.
- `source`: The source of the vulnerability (URL or form).
