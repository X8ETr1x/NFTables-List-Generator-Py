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

import ipaddress
import json
import re
from os import mkdir, path

import requests.exceptions
from requests import get


class ListParser:
    __slots__ = ['config_dir', 'output_dir', 'list_sets', 'net_regex_raw']

    def __init__(self, config_file):
        """
        Creates a new Rule Processor object.
        :param config_file: the absolute path to the configuration file.
        """
        print('Opening configuration file: ', config_file)

        try:
            with open(config_file, 'r') as file:
                configs = json.load(file)
                print('Configuration loaded.')
        except OSError as error:
            raise RuntimeError(f"Failed to open file {file.name}: {error}")
        except json.JSONDecodeError as error:
            raise RuntimeError(f"Invalid JSON format in file {file.name}: {error.msg}")

        try:
            self.config_dir = configs['config']['nftables_config_dir']
            self.output_dir = configs['config']['output_dir']
            self.list_sets = configs['lists']
        except KeyError as error:
            raise RuntimeError(f"Key does not exist: {error}")

        if not path.exists(self.output_dir):
            print('Directory', self.output_dir, 'does not exist. Creating...')
            try:
                mkdir(self.output_dir)
            except PermissionError as error:
                raise RuntimeError('Unable to create backup directory:', error)
        else:
            print('Setting output directory to ', self.output_dir)

        # Set the search regex object for extracting IPv4 addresses:
        self.net_regex_raw = re.compile(r'([0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3})((/[0-9]{1,2})?)')

    def get_list(self, url):
        """
        Retrieves and parses data from a threat intelligence network list, then yields each result.
        Due to the massive size of some lists, a generator is used.
        :param url: the URL of the list to be downloaded.
        :return: an IPv4Network object.
        """
        print('Downloading content from', url)
        try:
            r = get(url=url, stream=True)
            r.raise_for_status()
        except requests.ConnectionError as error:
            raise RuntimeError(f"Unable to connect to {url}: {error}")
        except requests.exceptions.MissingSchema as error:
            raise RuntimeError(f"Invalid URI scheme for {url}: {error}")
        except requests.ReadTimeout as error:
            raise RuntimeError(f"No data returned from {url}: {error}")
        except requests.RequestException as error:
            raise RuntimeError(f"Unexpected error accessing {url}: {error}")

        # Fallback encoding:
        if r.encoding is None:
            r.encoding = 'utf-8'

        # Parse the data into a new set:
        for line in r.iter_lines(decode_unicode=True):
            re_match = self.net_regex_raw.search(str(line))

            # Remove lines without an address:
            if re_match is None:
                continue

            # Validate the network address
            try:
                net = ipaddress.ip_network(re_match.group())
            except ValueError as error:
                print('Invalid network: ', error, '. Skipping.')
                continue

            # Skip private and reserved networks and addresses:
            if net.is_private:
                print('Skipping private address', net.with_prefixlen)
                continue

            # Add the filtered address to the new set:
            yield net

    def write_nft_file(self, net_list, file_name):
        """
        Creates a new NFT file and writes it to the designated directory.
        :param net_list: the set of summarized IPv4Network objects.
        :param file_name: the destination file name.
        :return: None when there's a blank list.
        """
        # Format and write the nft file:
        file_path = path.join(self.output_dir, file_name)
        list_count = 0
        list_limit = len(net_list) - 1

        try:
            with open(file_path, 'w') as file:
                print('Writing to file:', file_path)
                file.write(f"define {file_name.replace('.nft', '')} = {{\n")

                # Convert from IPv4Network object to string:
                while list_count < list_limit:
                    file.write(f"    {net_list[list_count].with_prefixlen.replace('/32', '')},\n")
                    list_count += 1

                file.write(f"    {net_list[list_count].with_prefixlen.replace('/32', '')}\n")
                file.write(f"}}\n")
                file.close()
        except OSError as error:
            raise RuntimeError(f"Error writing to {file_path}: {str(error)}")

    def write_nft_set(self, set_list, file_name):
        file_path = path.join(self.config_dir, file_name)
        list_count = 0
        list_limit = len(set_list) - 1

        try:
            with open(file_path, 'w') as file:
                print('Writing superset file:', file_path)
                file.write(f"define {file_name.replace('.nft', '')} = {{\n")

                while list_count < list_limit:
                    file.write(f"    {set_list[list_count]},\n")
                    list_count += 1

                file.write(f"    {set_list[list_count]}\n")
                file.write(f"}}\n")
                file.close()
        except OSError as error:
            raise RuntimeError(f"Error writing to {file_path}: {str(error)}")
