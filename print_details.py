import json

def print_cells_source():
    with open('Final.ipynb', 'r', encoding='utf-8') as f:
        data = json.load(f)
    
    cells_to_inspect = [24, 26, 28, 30, 34]
    with open('notebook_detailed_cells.txt', 'w', encoding='utf-8') as out:
        for idx in cells_to_inspect:
            if idx < len(data['cells']):
                cell = data['cells'][idx]
                out.write(f"=== CELL {idx:02d} ({cell['cell_type']}) ===\n")
                out.write("".join(cell.get('source', [])))
                out.write("\n\n")

if __name__ == '__main__':
    print_cells_source()
