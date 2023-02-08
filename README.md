# README

## Getting Started

Follow the steps below to run the program.

### Running the program

1. Get a free API Key [here](https://nvd.nist.gov/developers/request-an-api-key) 
2. Ensure your Python version is Python 3.9
3. Install dependencies
     ```pip install -r requirements.txt```
4. Enter your API key in `config.py`
   ```const API_KEY = 'ENTER YOUR API KEY';```
   1. Note: the constant is already in the file. Just change the string to be your API key.
5. From the terminal, inside the proper directory, run the program as follows:
   1. If you only want to detect vulnerabilities from a given pom file:
      1. ```python main.py detectOnly 'path/to/pom.xml'```
   2. If you want to completely reload the database from scratch (e.g. delete everything currently in the database and refill it with a fresh request from NVD)
      1. ```python main.py doAll 'path/to/pom.xml'```
         1. NOTE: This method will take a number of minutes. It will not print anything while querying the database.
6. After the program runs, open ```results.txt'``` to see the output of the program.