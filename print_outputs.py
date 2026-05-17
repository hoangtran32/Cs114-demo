import json

def print_notebook_outputs():
    with open('Final.ipynb', 'r', encoding='utf-8') as f:
        data = json.load(f)
    
    with open('notebook_outputs.txt', 'w', encoding='utf-8') as out:
        for i, cell in enumerate(data['cells']):
            if cell['cell_type'] == 'code' and cell.get('outputs'):
                out.write(f"=== CELL {i:02d} OUTPUTS ===\n")
                for output in cell['outputs']:
                    output_type = output.get('output_type')
                    if output_type == 'stream':
                        out.write("".join(output.get('text', [])))
                    elif output_type == 'execute_result':
                        out.write(json.dumps(output.get('data', {}), indent=2))
                out.write("\n\n")

if __name__ == '__main__':
    print_notebook_outputs()
