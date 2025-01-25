import csv
import json

tranco_file = "/home/jackfromeast/Desktop/TheHulk/dataset/Trenco_KJX3W.csv"  # Path to the Tranco list
error_report_files = ["/home/jackfromeast/Desktop/TheHulk/tasks/run-crawler-test/outputs/crawler-test-11-19-20-01/crawler-errors.json",
                     "/home/jackfromeast/Desktop/TheHulk/tasks/run-crawler-test/outputs/crawler-test-11-20-14-31/crawler-errors.json"]
output_file = "Trenco_KJX3W_Top5K_filtered.csv"  # Path for the output file

def load_error_domains(error_report_path):
    with open(error_report_path, "r") as file:
        error_data = json.load(file)
    return set(error_data["details"].keys())

# Load all error domains from multiple error reports
def load_all_error_domains(error_report_paths):
    all_error_domains = set()
    for path in error_report_paths:
        all_error_domains.update(load_error_domains(path))
    return all_error_domains

# Load the Tranco list
def load_tranco_list(tranco_path):
    tranco_domains = []
    with open(tranco_path, "r") as file:
        reader = csv.reader(file)
        for row in reader:
            # row[1] contains the domain
            tranco_domains.append(row)
    return tranco_domains

# Filter the Tranco list
def filter_tranco_list(tranco_domains, error_domains, limit=5000):
    filtered_domains = []
    seen_domains = set()  # To ensure deduplication
    for _, domain in tranco_domains:
        if domain not in error_domains and domain not in seen_domains:
            filtered_domains.append(domain)
            seen_domains.add(domain)
        if len(filtered_domains) >= limit:
            break
    return filtered_domains

# Save the filtered list to a CSV with continuous indices
def save_filtered_list(filtered_domains, output_path):
    with open(output_path, "w", newline="") as file:
        writer = csv.writer(file)
        for i, domain in enumerate(filtered_domains, start=1):
            writer.writerow([i, domain])

def main():
    error_domains = load_all_error_domains(error_report_files)
    tranco_domains = load_tranco_list(tranco_file)
    filtered_domains = filter_tranco_list(tranco_domains, error_domains)
    save_filtered_list(filtered_domains, output_file)
    print(f"Filtered list saved to {output_file}")

if __name__ == "__main__":
    main()