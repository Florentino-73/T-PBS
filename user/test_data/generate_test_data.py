#!/usr/bin/env python3
"""
Generate synthetic GWAS test data files for T-PBS.

Each .gwas file contains a binary SNP record with:
  - user_type (1 byte)
  - homo_num (4 bytes, uint32)
  - SNPs array (uint32 values)

Usage:
    python3 generate_test_data.py [--count 5000] [--output generated_gwas]
"""

import argparse
import os
import struct
import random

SNP_COUNT = 740  # Number of SNP entries per file


def generate_gwas_file(filepath: str, data_id: int) -> None:
    """Generate a single synthetic .gwas file."""
    user_type = random.randint(0, 1)
    homo_num = random.randint(0, SNP_COUNT)
    snps = [random.getrandbits(32) for _ in range(SNP_COUNT)]

    with open(filepath, "wb") as f:
        f.write(struct.pack("<B", user_type))
        f.write(struct.pack("<I", homo_num))
        for snp in snps:
            f.write(struct.pack("<I", snp))


def main():
    parser = argparse.ArgumentParser(description="Generate synthetic GWAS test data")
    parser.add_argument("--count", type=int, default=5000, help="Number of files to generate (default: 5000)")
    parser.add_argument("--output", type=str, default="generated_gwas", help="Output directory (default: generated_gwas)")
    args = parser.parse_args()

    os.makedirs(args.output, exist_ok=True)

    for i in range(args.count):
        filename = os.path.join(args.output, f"{i:08x}.gwas")
        generate_gwas_file(filename, i)
        if (i + 1) % 1000 == 0:
            print(f"Generated {i + 1}/{args.count} files")

    print(f"Done. Generated {args.count} files in {args.output}/")


if __name__ == "__main__":
    main()
