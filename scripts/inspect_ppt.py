import zipfile
import xml.etree.ElementTree as ET
import os
import sys

# Ensure stdout encodes properly
sys.stdout.reconfigure(encoding='utf-8', errors='replace')

pptx_path = 'CipherTwin_Capstone_VERIFIED.pptx'
if not os.path.exists(pptx_path):
    print("PPTX not found:", pptx_path)
    exit(1)

with zipfile.ZipFile(pptx_path, 'r') as z:
    slide_files = sorted(
        [n for n in z.namelist() if n.startswith('ppt/slides/slide') and n.endswith('.xml')],
        key=lambda x: int(''.join(filter(str.isdigit, x)) or 0)
    )
    print(f"Total slides found: {len(slide_files)}\n")
    for sf in slide_files:
        tree = ET.fromstring(z.read(sf))
        texts = [node.text.strip() for node in tree.iter() if node.text and node.text.strip()]
        slide_num = sf.split('/')[-1].replace('.xml', '')
        print(f"==================== SLIDE: {slide_num} ====================")
        print("\n".join(texts))
        print("\n")
