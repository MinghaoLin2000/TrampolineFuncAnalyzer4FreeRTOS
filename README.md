# CodeqlForFreertos
we implement an automatic tool based on Codeql. The tool mainly is used to scan arbitrary write and read as well as DOS for Freertos. 

## Usage

1. Please install and configure the codeql correctly.
2. Import the rtosdatabase3 which is a source code database of Freertos for codeql to scan.
3. run the script which is located in CodeqlForFreertos/vscode-codeql-starter/codeql-custom-queries-cpp/example.ql

## Attention
- The rtosdatabase3 included all MPU_ functions. We have added some functions that were not enabled by macro definitions into the database by modifying the code, ensuring that every function can be scanned.
- We recommend operating the script in VSCode for a more convenient experience.
- There are three scanning modes available. You can choose which one to run, but manual further auditing is still required.
