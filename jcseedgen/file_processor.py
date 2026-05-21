import os
import ast

def write_byte_lines_to_files(input_string: str, output_dir: str):
    os.makedirs(output_dir, exist_ok=True)

    lines = input_string.strip().splitlines()

    for i, line in enumerate(lines):
        line = line.strip()
        if not line:
            continue

        # Split into name and bytes literal (single space delimiter)
        try:
            name, bytes_literal = line.split(" ", 1)
        except ValueError:
            raise ValueError(f"Line {i} does not contain a name and bytes literal")

        # Convert "b'...'" string into actual bytes
        data = ast.literal_eval(bytes_literal)

        if not isinstance(data, (bytes, bytearray)):
            raise ValueError(f"Line {i} does not contain a valid bytes literal")

        # Use the provided snake_case name for the file
        file_path = os.path.join(output_dir, f"{name}.bin")

        with open(file_path, "wb") as f:
            f.write(data)
