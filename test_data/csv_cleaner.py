import csv

with open('parsed_dataset.csv', newline='') as in_file:
    with open('balanced_malicious_benign.csv', 'w', newline='') as out_file:
        writer = csv.writer(out_file)
        for row in csv.reader(in_file):
            if row:
                writer.writerow(row)