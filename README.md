# sast-visu-tools

Set of custom SAST output reports visualisation tools

## 1. visu-semgrep

### 1.1. Description

A tool that reads a semgrep-report json file and displays the results in a more readable way in the CLI.

### 1.2. Usage

```bash
# With the Python script
python3 visu-semgrep.py --all <path_to_semgrep_report.json>
# With the Bash script
./visu-semgrep.sh --all <path_to_semgrep_report.json>
```

> ℹ️ Note: The `-a` or `--all` will execute all the available options. If you want to get a list of the available options, you can use the `-h` or `--help` flag.

### 1.3 Example

![visu-semgrep Example](./images/visu-semgrep_example.png)

## 2. visu-semgrep-ci

### 2.1. Description

A tool that reads a semgrep-report json file and displays the results in a more readable way in the CLI and in a text file. This tool is designed to be used in a CI/CD pipeline.

### 2.2. Usage

```bash
# With the Python script
python3 visu-semgrep-ci.py --all <path_to_semgrep_report.json> <output_file>
# With the Bash script
./visu-semgrep-ci.sh --all <path_to_semgrep_report.json> <output_file>
```

> ℹ️ Note: The `-a` or `--all` will execute all the available options. If you want to get a list of the available options, you can use the `-h` or `--help` flag.

### 2.3. Example

![visu-semgrep-ci Example](./images/visu-semgrep-ci_example.png)

## 3. semgrep-custom

### 3.1. Description

A custom installation of semgrep that includes a set of custom rules as well as the ***visu-semgrep-ci*** tool. It is designed to be used in a CI/CD pipeline.

### 3.2. Usage

```bash
# With the Python script
python3 semgrep-custom.py <path_to_semgrep_report.json> <output_file>
# With the Bash script
./semgrep-custom.sh <path_to_semgrep_report.json> <output_file>
```

### 3.3. Example

```yaml
# Example with a GitHub Actions workflow file
name: Semgrep OSS scan
on:
    push:
        branches: ["master", "main"]
jobs:
    semgrep:
        name: semgrep-oss-custom/scan
        runs-on: ubuntu-latest
        container:
            image: ahddry/semgrep-custom:latest
        steps:
            - uses: actions/checkout@v4
            - name: Run Semgrep custom scan
              run: semgrep-custom . .
            - name: Upload semgrep artifact
              uses: actions/upload-artifact@v4
              with:
                  name: semgrep-results
                  path: semgrep-report.json
```

![Example](./images/semgrep-custom_example.png)

## 4. visu-parser

### 4.1. Description

A tool that reads a semgrep-report json file or a sarif report file from a SAST tool, parse it as a normalised json file and sends if possible the report to a NOSQL MongoDB database. It is designed to be used in a CI/CD pipeline.

### 4.2. Usage

To use the tool, you need to have a MongoDB database running with a collection named `reports` and another named `projects`.

In your CI/CD environment, you need to set the following environment variables:

- `PROJECT_ID`: The ID of the current project (numeric value)
- `MONGODB_URL`: The URL of the MongoDB database (e.g. `url.example.com:27017`)
- `MONGODB_USERNAME`: The username of the MongoDB database (e.g. `admin`)
- `MONGODB_PASSWORD`: The password of the MongoDB database (e.g. `password`)

```bash
# With the Python script
python3 visu-parser.py <path_to_report.json|sarif>
```

### 4.3. Example

```yaml
# Example with a GitHub Actions workflow file
name: Semgrep OSS scan
on:
    push:
        branches: ["master", "main"]
jobs:
    semgrep:
        name: semgrep-oss-custom/scan
        runs-on: ubuntu-latest
        container:
            image: ahddry/semgrep-custom:latest
        steps:
            - uses: actions/checkout@v4
            - name: Run Semgrep custom scan
              run: semgrep-custom . .
            - name: Upload semgrep artifact
              uses: actions/upload-artifact@v4
              with:
                  name: semgrep-results
                  path: semgrep-report.json
            - name: Parse results and upload to database
              env:
                  PROJECT_ID: ${{ secrets.PROJECT_ID }}
                  MONGODB_URL: ${{ secrets.MONGODB_URL }}
                  MONGODB_USERNAME: ${{ secrets.MONGODB_USERNAME }}
                  MONGODB_PASSWORD: ${{ secrets.MONGODB_PASSWORD }}
              run: python visu-parser.py semgrep-report.json
```
