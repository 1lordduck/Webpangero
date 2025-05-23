# WebPangero

WebPangero is a **simple** web scanner designed to quickly and easily scan websites. It is lightweight and fast, making it ideal for users who need to quickly analyze websites for certain information.

This project was started as a way to learn and practice my knowledge in web development and scanning tools, and for fun of course.

## Features

- Fast and efficient website scanning.
- Simple and easy-to-use interface.
- Lightweight and minimal dependencies.
    
## Changelog (v0.0.3)

### Added
- Proper SQLi detection

## Installation

### Requirements

Before you begin, ensure you have the following installed:

- Python 3.x
- Required libraries listed in `requirements.txt`

### Steps

1. Clone the repository:
   ```bash
   git clone https://github.com/1lordduck/WebPangero.git
   cd WebPangero
   ```

2. Install the dependencies:
   ```bash
   pip install -r requirements.txt
   ```

3. Run the scanner:
   ```bash
   python3 webscanner.py -u https://example.com -T 22
   ```

## Usage

WebPangero allows you to scan a website by providing either a URL (`-u`) or a file (`-f`) containing URLs. You can also set a threshold value (`-T`).

### Available options:

- `-u URL`: Provide a URL of the website you want to scan.
- `-f FILE`: Provide a HTML file to scan.
- `-T THRESHOLD`: Set a threshold value for scanning (you can customize the threshold logic in your code).
  
### Example 1: Scan a single URL
```bash
python3 webscanner.py -u https://pentest-ground.com:4280/vulnerabilities/xss_s/ -T 22
```

### Example 2: Scan a html file
```bash
python3 webscanner.py -f awesomesite.html -T 22
```

The scanner will then perform the scan and return results based on the information found (such as vulnerabilities)

## License

WebPangero is licensed under the MIT License. See `LICENSE` for more details.
