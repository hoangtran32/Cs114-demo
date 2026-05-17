import json

def parse_notebook():
    with open('Final.ipynb', 'r', encoding='utf-8') as f:
        data = json.load(f)
    
    with open('notebook_summary.txt', 'w', encoding='utf-8') as out:
        out.write(f"Number of cells: {len(data['cells'])}\n\n")
        for i, cell in enumerate(data['cells']):
            cell_type = cell['cell_type']
            source = "".join(cell.get('source', []))
            first_line = source.split('\n')[0] if source else ""
            out.write(f"Cell {i:02d} | {cell_type:<8} | {first_line[:120]}\n")
            # If it's code, write some more lines to understand
            if cell_type == 'code':
                lines = source.split('\n')
                for line in lines[1:5]:
                    if line.strip():
                        out.write(f"        {line[:100]}\n")
            out.write("\n")

if __name__ == '__main__':
    parse_notebook()
