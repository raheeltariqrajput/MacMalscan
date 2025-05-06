# macmalscan/cli.py
import argparse
from macmalscan import analyze_file, get_main_executable

def main():
    parser = argparse.ArgumentParser(description="Malware analysis CLI")
    parser.add_argument('file', help="Path to the file or .app bundle to analyze")
    args = parser.parse_args()

    if args.file.endswith('.app'):
        executable = get_main_executable(args.file)
        if executable:
            print(f"Main executable found: {executable}")
            result = analyze_file(executable)
        else:
            print("No executable found in the .app bundle.")
    else:
        result = analyze_file(args.file)

    print(f"Analysis complete. Risk score: {result['risk_score']}")

if __name__ == '__main__':
    main()
