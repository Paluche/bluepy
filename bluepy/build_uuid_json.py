#!/usr/bin/env python3
"""
Build up UUID JSON from the Bluetooth ORG website.
"""

import sys
import json
from argparse import ArgumentParser, FileType
import requests
from bs4 import BeautifulSoup


BLUETOOTH_ORG_URL = 'https://developer.bluetooth.org'
BLUETOOTH_ORG_GATT_URL = f'{BLUETOOTH_ORG_URL}/gatt/'


def get_table_rows(url):
    request = requests.get(url)
    if request.status_code != 200:
        raise ValueError(
            f'Unable to get table from {BLUETOOTH_ORG_URL} code '
            f'{request.status_code}'
        )
    soup = BeautifulSoup(request.content)
    tables = soup.find_all('table')

    biggest_table = max(tables, key=len)

    # service_table = soup.find(
    #     'table',
    #     attrs={
    #         'summary': 'Documents This library contains Services.'
    #     }
    # )

    assert biggest_table

    for row in biggest_table.find_all('tr'):
        ret = []
        columns = row.find_all('td')

        for element in columns:
            element = element.text.strip()
            if not element:
                continue
            ret.append(element)

        if ret:
            yield ret


def get_table(url, table_defs):
    """ Grabs the largest table from a webpage.

    table_defs is a list of column name, interpretation function.
    """
    for row in get_table_rows(url):
        assert len(row) == len(table_defs)

        ret = []
        for col, (name, func) in zip(row, table_defs):
            try:
                if func is None:
                    ret[name] = col
                else:
                    ret[name] = func(col)
            except:
                print(name)
                print(col)
                print(row)
                raise
        yield ret

def get_services():
    rows = get_table(
        BLUETOOTH_ORG_GATT_URL + 'services/Pages/ServicesHome.aspx',
        (('Name', None),
         ('Type', None),
         ('Number', lambda x: int(x, 16)),
         ('Level', None))
    )

    for row in rows:
        row['cname'] = row['Type'].split('.')[-1]
        yield row


def get_descriptors():
    rows = get_table(
        BLUETOOTH_ORG_GATT_URL + 'descriptors/Pages/DescriptorsHomePage.aspx',
        (('Name', None),
         ('Type', None),
         ('Number', lambda x: int(x, 16)),
         ('Level', None))
    )
    for row in rows:
        row['cname'] = row['Type'].split('.')[-1]
        yield row


def get_characteristics():
    rows = get_table(
        (BLUETOOTH_ORG_GATT_URL +
         'characteristics/Pages/CharacteristicsHome.aspx'),
        (('Name', None),
         ('Type', None),
         ('Number', lambda x: int(x, 16)),
         ('Level', None))
    )
    for row in rows:
        row['cname'] = row['Type'].split('.')[-1]
        yield row


def get_units():
    rows = get_table(
        BLUETOOTH_ORG_GATT_URL + 'units/Pages/default.aspx',
        (('Number', lambda x: int(x, 16)), ('Name', None), ('Type', None))
    )
    for row in rows:
        row['cname'] = row['Type'].split('.')[-1]
        yield row


def get_formats():
    rows = get_table(
        BLUETOOTH_ORG_GATT_URL + 'Pages/FormatTypes.aspx',
        (('Name', None), ('Description', None))
    )
    for row in rows:
        row['cname'] = row['Name']
        yield row


def main():
    """Main method."""
    parser = ArgumentParser(description=__doc__)

    parser.add_argument(
        '-o',
        '--output',
        dest='output',
        type=FileType('w'),
        default=sys.stdout,
        help='Write the UUID JSON into a file, otherwise it will be printed '
             'on stdout'
    )

    parsed = parser.parse_args()

    data = {
        'characteristic_UUIDs': [(row['Number'], row['cname'], row['Name'])
                                 for row in get_characteristics()],
        'service_UUIDs': [(row['Number'], row['cname'], row['Name'])
                          for row in get_services()],
        'descriptor_UUIDs': [(row['Number'], row['cname'], row['Name'])
                             for row in get_descriptors()],
        'units_UUIDs': [(row['Number'], row['cname'], row['Name'])
                        for row in get_units()],
        'formats': [(row['Name'], row['Description'])
                    for row in get_formats()],
    }

    print(json.dumps(data,
                     indent=4,
                     encoding='utf-8',
                     ensure_ascii=False,
                     sort_keys=True),
          file=parsed.output_file)


if __name__ == '__main__':
    main()
