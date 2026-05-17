import json

def extract_extractor():
    with open('Final.ipynb', 'r', encoding='utf-8') as f:
        data = json.load(f)
    
    # Cell 03 contains the PEFeatureExtractor and FeatureType classes
    cell_3 = data['cells'][3]
    code = "".join(cell_3.get('source', []))
    
    with open('pe_extractor.py', 'w', encoding='utf-8') as out:
        out.write(code)
    print("Successfully extracted class definition to pe_extractor.py!")

if __name__ == '__main__':
    extract_extractor()
