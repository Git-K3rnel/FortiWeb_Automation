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
