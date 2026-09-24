# NFTables List Generator

A Python program that retrieves IP lists and summarizes them into an nftables script.

The program ingests a JSON formatted file with configuration parameters and data sources. Once loaded, it will retrieve each list, search each line for a valid IP address or subnet, parse out dangerous values such as `0.0.0.0`, and output a script file to the desired directory.

An example copy of `fw_data.json` is provided as a guideline for the configuration file.