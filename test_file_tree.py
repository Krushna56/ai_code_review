"""
Test script to verify flatten_file_tree function works correctly
"""
import os
import sys

# Add parent directory to path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

def generate_file_tree(base_path, relative_path=""):
    """Generate a nested dictionary representing the file structure with relative paths"""
    full_path = os.path.join(base_path, relative_path)
    item_name = os.path.basename(relative_path) if relative_path else "Project Root"
    
    tree = {'name': item_name, 'type': 'directory', 'children': []}
    
    try:
        items = sorted(os.listdir(full_path))
        for item in items:
            item_rel_path = os.path.join(relative_path, item)
            item_full_path = os.path.join(base_path, item_rel_path)
            
            if os.path.isdir(item_full_path):
                tree['children'].append(generate_file_tree(base_path, item_rel_path))
            else:
                tree['children'].append({
                    'name': item,
                    'type': 'file',
                    'path': item_rel_path.replace('\\', '/')  # Ensure forward slashes for web
                })
    except Exception as e:
        print(f"Error generating file tree: {e}")
        
    return tree


def flatten_file_tree(tree_node, result=None):
    """Flatten nested file tree into a list of file objects for frontend"""
    if result is None:
        result = []
    
    if tree_node.get('type') == 'file':
        # Add file to result
        result.append({
            'name': tree_node['name'],
            'path': tree_node['path'],
            'type': 'file'
        })
    elif tree_node.get('type') == 'directory' and 'children' in tree_node:
        # Recursively process children
        for child in tree_node['children']:
            flatten_file_tree(child, result)
    
    return result


if __name__ == "__main__":
    # Test with current directory
    test_path = "."
    
    print("Testing file tree generation...")
    print(f"Test path: {os.path.abspath(test_path)}\n")
    
    # Generate nested tree
    tree = generate_file_tree(test_path)
    print(f"Generated tree structure:")
    print(f"  Root: {tree['name']}")
    print(f"  Children count: {len(tree.get('children', []))}\n")
    
    # Flatten tree
    flat_tree = flatten_file_tree(tree)
    print(f"Flattened tree:")
    print(f"  Total files: {len(flat_tree)}")
    
    if flat_tree:
        print(f"\nFirst 5 files:")
        for i, file in enumerate(flat_tree[:5]):
            print(f"  {i+1}. {file['path']}")
    else:
        print("\n⚠️ WARNING: No files found!")
    
    print("\n✅ Test complete")
