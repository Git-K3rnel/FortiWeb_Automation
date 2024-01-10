import csv

csv_data = {}
with open('csv_file.csv', 'r') as file1:
    for line_number,line in enumerate(file1):
        tempList = []
        # print(line_number)
        clean_line = line.rstrip('\n').strip()
        split_data = clean_line.split(',')
        tempList.append(line_number)
        tempList.append(split_data[1])
        csv_data[split_data[0]] = tempList


input_file_data = {}
with open('input_file.txt', 'r', encoding='utf8') as file2:
    input_file_lines = file2.readlines()
    for line in input_file_lines:
        clean_line = line.rstrip('\n').strip()

        split_data = clean_line.split('||')
        input_file_data[split_data[0]] = split_data[1]


with open('csv_file.csv', 'r', encoding='utf8') as file3:
    reader = csv.reader(file3)
    existing_data = list(reader)

# print(existing_data)

for key1 in input_file_data.keys():
    for key2 in csv_data.keys():
        if key1 == csv_data[key2][1]:
            row_index = csv_data[key2][0]
            new_data = input_file_data[key1]
            existing_data[row_index] += new_data
            with open('csv_file.csv', 'w', newline='', encoding='utf8') as file4:
                writer = csv.writer(file4)
                writer.writerows(existing_data)
