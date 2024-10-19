import csv
import openpyxl
import pandas as pd
from falconpy import ReportExecutions
from datetime import datetime
import os

CROWDSTRIKE_CLIENT_ID = os.getenv("CROWDSTRIKE_CLIENT_ID")
CROWDSTRIKE_CLIENT_SECRET = os.getenv("CROWDSTRIKE_CLIENT_SECRET")
CROWDSTRIKE_REPORT_ID = os.getenv("CROWDSTRIKE_REPORT_ID")

def retrieve_report_executions(sdk: ReportExecutions, rptid: str):
    """Retrieve the list of execution IDs that match this report ID."""
    print(f"Searching for executions of {rptid}")
    execution_id_lookup = sdk.reports_executions_query(filter=f"scheduled_report_id:'{rptid}'")
    if not execution_id_lookup["status_code"] == 200:
        raise SystemExit("Unable to retrieve report executions from "
                         "the CrowdStrike API, check API key permissions.")

    return sdk, execution_id_lookup["body"]["resources"]

def get_report_execution_runs(sdk: ReportExecutions, id_list: list):
    """Retrieve the list of execution runs for each execution ID."""
    print(f"Found {len(id_list)} executions of this report available.")
    exec_status_lookup = sdk.report_executions_get(id_list)
    if not exec_status_lookup["status_code"] == 200:
        raise SystemExit("Unable to retrieve execution statuses from the CrowdStrike API.")
    print(f"This execution has run {len(exec_status_lookup['body']['resources'])} times.")
    return sdk, exec_status_lookup["body"]["resources"]

def process_executions(sdk: ReportExecutions, run_list: list):
    """Process the results of the executions, handle bytes and write them to Excel."""
    sorted_runs = sorted(run_list, key=lambda x: x.get("created_on"), reverse=True)[:2]
    saved_files = []

    for exec_status in sorted_runs:
        status = exec_status["status"]
        exec_id = exec_status["id"]
        rpt_id = exec_status["scheduled_report_id"]

        created_on_str = exec_status.get("created_on", "Unknown Date")
        if created_on_str != "Unknown Date":
            created_on_str = created_on_str[:26] + "Z"
            created_on_date = datetime.strptime(created_on_str, "%Y-%m-%dT%H:%M:%S.%fZ")
            date_suffix = created_on_date.strftime("%Y%m%d")
        else:
            date_suffix = "unknown"

        if status.upper() == "DONE":
            print(f"Retrieving report detail for execution ID: {exec_id}")
            report_detail = sdk.get_download(exec_id)
            if report_detail:
                if isinstance(report_detail, bytes):
                    try:
                        decoded_data = report_detail.decode('utf-8')
                        rows = decoded_data.splitlines()

                        workbook = openpyxl.Workbook()
                        sheet = workbook.active
                        reader = csv.reader(rows)

                        for row in reader:
                            sheet.append(row)

                        excel_filename = f"{exec_id}_{date_suffix}.xlsx"
                        workbook.save(excel_filename)
                        saved_files.append(excel_filename)
                        print(f"{exec_id} successfully saved to {excel_filename}")

                    except Exception as e:
                        print(f"Failed to process report {exec_id}. Error: {str(e)}")
                else:
                    print(f"Report detail is not in bytes format, cannot process execution {exec_id}.")
            else:
                print(f"Unable to retrieve report for execution {exec_id} of {rpt_id}.")
        else:
            print(f"Skipping {exec_id} as not yet finished.")

    return saved_files

def read_file(file_path):
    """Reads an Excel file."""
    return pd.read_excel(file_path)

def compare_excel_files(file1, file2):
    """Compare two Excel files and return unique values in the second file."""
    older_data = read_file(file1)
    newer_data = read_file(file2)

    older_data = older_data.dropna(subset=['CVE ID'])
    newer_data = newer_data.dropna(subset=['CVE ID'])

    comparison = pd.merge(newer_data, older_data, on=['CVE ID', 'Image repository', 'Image tag', 'Image name', 'Image registry'], how='left', indicator=True)
    unique_values = comparison[comparison['_merge'] == 'left_only']

    current_date = datetime.now().strftime('%Y_%m_%d')
    output_file_name = f'{current_date}_ImageVulnerabilityAssessment.xlsx'

    unique_values[['CVE ID', 'Image repository', 'Image tag', 'Image name', 'Image registry']].to_excel(output_file_name, index=False)

    print(f"The data has been successfully saved to {output_file_name}.")
    return output_file_name

if __name__ == "__main__":
    falcon = ReportExecutions(client_id=CROWDSTRIKE_CLIENT_ID, client_secret=CROWDSTRIKE_CLIENT_SECRET)

    saved_files = process_executions(
        *get_report_execution_runs(*retrieve_report_executions(falcon, CROWDSTRIKE_REPORT_ID))
    )

    if len(saved_files) == 2:
        file1, file2 = saved_files
        output_file = compare_excel_files(file1, file2)
    else:
        print("Not enough files saved for comparison.")
