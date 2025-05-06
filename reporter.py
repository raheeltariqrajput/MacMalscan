import os
import subprocess
import webbrowser
from datetime import datetime

# Helper function to run strings extraction
def extract_strings_from_binary(file_path):
    """Runs the 'strings' command on Unix-based systems or 'strings.exe' on Windows."""
    try:
        # Check for OS and run the appropriate command
        if os.name == 'posix':
            result = subprocess.run(['strings', file_path], capture_output=True, text=True)
        elif os.name == 'nt':
            result = subprocess.run(['strings.exe', file_path], capture_output=True, text=True)
        else:
            raise NotImplementedError("Unsupported operating system")

        # Return the extracted strings
        if result.returncode == 0:
            return result.stdout.splitlines()
        else:
            print("Error extracting strings:", result.stderr)
            return []
    except Exception as e:
        print("Error running strings command:", e)
        return []

# Ensure the 'reports' directory exists
def ensure_dir(directory):
    if not os.path.exists(directory):
        os.makedirs(directory)

# Generate the HTML report
def generate_report(result):
    # Report directory within the project folder
    report_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'reports')
    ensure_dir(report_dir)

    # File details for naming the report
    base_name = os.path.basename(result['file'])
    timestamp = datetime.now().strftime('%Y-%m-%d_%H-%M-%S')
    report_file_name = f"{base_name}_{timestamp}.html"
    report_path = os.path.join(report_dir, report_file_name)

    # Create the HTML report content
    report_content = f"""
    <html>
        <head>
            <title>Malware Analysis Report: {base_name}</title>
            <style>
                body {{
                    font-family: Arial, sans-serif;
                    margin: 0;
                    padding: 20px;
                    background-color: #f9f9f9;
                }}
                h1 {{
                    color: #333;
                }}
                .container {{
                    width: 80%;
                    margin: auto;
                    padding: 10px;
                }}
                .section {{
                    background-color: #fff;
                    padding: 10px;
                    margin: 10px 0;
                    border-radius: 5px;
                    box-shadow: 0 2px 5px rgba(0, 0, 0, 0.1);
                }}
                table {{
                    width: 100%;
                    border-collapse: collapse;
                    margin-top: 10px;
                }}
                table, th, td {{
                    border: 1px solid #ddd;
                }}
                th, td {{
                    padding: 8px;
                    text-align: left;
                }}
                th {{
                    background-color: #f2f2f2;
                }}
                .footer {{
                    font-size: 12px;
                    color: #999;
                    text-align: center;
                    margin-top: 20px;
                }}
            </style>
        </head>
        <body>
            <div class="container">
                <h1>Malware Analysis Report: {base_name}</h1>
                <p><strong>Analysis Date:</strong> {timestamp}</p>

                <div class="section">
                    <h2>File Details</h2>
                    <p><strong>File:</strong> {result['file']}</p>
                    <p><strong>Total Strings Extracted:</strong> {result['total_strings']}</p>
                    <p><strong>Risk Score:</strong> {result['risk_score']}</p>
                </div>

                <div class="section">
                    <h2>Indicators Found</h2>
                    <h3>IPs:</h3>
                    <ul>
                        {"".join([f"<li>{ip}</li>" for ip in result['indicators']['IPs']])}
                    </ul>

                    <h3>URLs:</h3>
                    <ul>
                        {"".join([f"<li>{url}</li>" for url in result['indicators']['URLs']])}
                    </ul>

                    <h3>Base64 Strings:</h3>
                    <ul>
                        {"".join([f"<li>{b64}</li>" for b64 in result['indicators']['Base64']])}
                    </ul>

                    <h3>APIs:</h3>
                    <ul>
                        {"".join([f"<li>{api}</li>" for api in result['indicators']['APIs']])}
                    </ul>

                    <h3>Persistence Indicators:</h3>
                    <ul>
                        {"".join([f"<li>{persistence}</li>" for persistence in result['indicators']['Persistence']])}
                    </ul>
                </div>

                <div class="section">
                    <h2>Behaviors Detected</h2>
                    <ul>
                        {"".join([f"<li>{behavior}</li>" for behavior in result['behaviors']])}
                    </ul>
                </div>

                <div class="section">
                    <h2>Malware Family Detection</h2>
                    <p><strong>Detected Malware Family:</strong> {result['family']}  ({result['family_description']})</p>
                </div>

                <div class="footer">
                    <p>This report was generated by MacMalscan. For more information, visit the <a href="https://github.com/yourusername/macmalscan">MacMalscan GitHub</a>.</p>
                </div>
            </div>
        </body>
    </html>
    """

    # Write the report content to the file
    with open(report_path, 'w') as report_file:
        report_file.write(report_content)

    # Automatically open the report in a browser
    webbrowser.open(f'file://{os.path.abspath(report_path)}')

    print(f"Report generated: {report_path}")
    return report_path