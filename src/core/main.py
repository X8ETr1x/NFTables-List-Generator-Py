#!/usr/bin/python
# -*- coding: utf-8 -*-

__author__ = 'X8ETR1x'
__copyright__ = 'Copyright 2026, X8ETr1x'
__credits__ = ['X8ETr1x']
__date__ = '2026-09-23'
__email__ = 'codestuff@thetrixster.com'
__license__ = 'GPL-3.0'
__maintainer__ = 'X8ETr1x'
__status__ = 'Production'
__version__ = '1.0.0'

import gc
from argparse import ArgumentParser
from ipaddress import collapse_addresses
from sys import exit

from src.services.list_parser import ListParser


def main():
    # Get CLI arguments
    parser = ArgumentParser(description='Retrieve and format IP lists for nftables.')
    parser.add_argument('--consolidate',
                        action='store_true',
                        help='Consolidate the lists into category lists (extremely memory intensive). Cannot be '
                             'combined with --summarize.')
    parser.add_argument('--data-file',
                        type=str,
                        help=' Absolute path to the list data file.',
                        required=True)
    parser.add_argument('--summarize',
                        action='store_true',
                        help='Summarize the lists before writing to disk (memory intensive). Cannot be combined with '
                             '--consolidate.')
    args = parser.parse_args()

    if args.consolidate and args.summarize:
        print('Consolidate and summarize options are mutually exclusive.')
        parser.print_help()
        exit(1)

    consolidate = False
    if args.consolidate:
        consolidate = True

    try:
        lp = ListParser(config_file=args.data_file)
    except RuntimeError as error:
        print('Error caught during runtime: ', error)
        exit(1)

    # Iterate through the traffic directions e.g. ingress, egress:
    for classification in lp.list_sets.keys():
        nft_superset = set()

        for url in lp.list_sets[classification]:
            nft_set = set()

            try:
                # Create a generator object for results to reduce memory consumption:
                url_data = lp.get_list(url=url)
            except RuntimeError as error:
                # Skip if the URL was unreachable
                print('Error caught during runtime: ', error)
                continue

            # Add the returned IPv4 objects to a new set:
            while True:
                try:
                    net = next(url_data)
                    nft_set.add(net)
                except StopIteration:
                    break

            # Skip if there's no data:
            if not nft_set:
                continue

            if args.summarize:
                nft_set = set(collapse_addresses(nft_set))

            if consolidate:
                nft_superset = sorted(nft_superset.union(nft_set))
                del nft_set
                gc.collect()
                nft_superset = set(collapse_addresses(nft_superset))
                continue

            # Write the nftables set file:
            nft_set = list(nft_set)
            nft_set_name = url.rsplit('/', 1)[1]
            nft_set_name_file = nft_set_name + '.nft'

            try:
                lp.write_nft_file(net_list=nft_set, file_name=nft_set_name_file)
            except RuntimeError as error:
                print('Error caught during runtime: ', error)
                print('Skipping file', nft_set_name_file)

            del nft_set
            gc.collect()
            nft_superset.add(nft_set_name)

        if consolidate:
            # Write the reference set file:
            nft_superset = list(nft_superset)
            nft_superset_file = classification + '.nft'

            try:
                lp.write_nft_file(net_list=nft_superset, file_name=nft_superset_file)
            except RuntimeError as error:
                print('Error caught during runtime: ', error)
                print('Reference set file', nft_superset_file, 'not created!')

    print('List creation completed!')
    exit(0)
