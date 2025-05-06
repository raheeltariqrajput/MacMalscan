from setuptools import setup, find_packages

setup(
    name="macmalscan",  # Name of your package
    version="0.1.0",  # Version number (update as needed)
    description="A malware analysis tool for macOS applications",
    long_description=open("README.md").read(),
    long_description_content_type="text/markdown",  # Ensures the README is rendered in markdown
    author="Your Name",
    author_email="your.email@example.com",  # Update with your email
    url="https://github.com/yourusername/macmalscan",  # Replace with your GitHub repo URL
    packages=find_packages(),  # Automatically finds and includes your package's modules
    install_requires=[  # List of required dependencies
        "pyyaml",
        "requests",  # List any other libraries your package depends on
    ],
    entry_points={  # Specifies the command-line interface for your package
        'console_scripts': [
            'macmalscan-cli=macmalscan.cli:main',  # Replace 'main' with your CLI entry function
        ],
    },
    classifiers=[  # Optional: Add classifiers to describe your package
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
    ],
    python_requires='>=3.6',  # Specify the Python version compatibility
)
