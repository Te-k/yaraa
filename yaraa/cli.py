import os
import sys
import argparse
import yaml
from subprocess import call
from .yaraa import lookup

CONFIG_PATH = os.path.join(os.path.expanduser("~"), ".yaraa")


def read_config() -> dict:
    """
    Read configuration and return a dictionary
    """
    if os.path.isfile(CONFIG_PATH):
        with open(CONFIG_PATH, 'r') as f:
            config = yaml.safe_load(f)
        return config
    else:
        return {'files': []}


def main():
    parser = argparse.ArgumentParser(description='Advanced Yara checking')
    parser.add_argument('FILE', help='File to be checked')
    parser.add_argument('--rules', '-r', help='Yara rules')
    parser.add_argument('--recursive', '-R', action='store_true', help='Recursive search (for folders only)')
    parser.add_argument('--verbose', '-v', action='count', default=0, help="Verbose")
    args = parser.parse_args()

    # Identify rules
    if args.rules:
        if not os.path.isfile(args.rules):
            print("No such rule file")
            sys.exit(1)
        rules = [args.rules]
    else:
        config = read_config()
        if len(config['files']) > 0:
            rules = config['files']
        else:
            print("No yara rule configured, please add rules with yaraa-config or with -r")
            sys.exit(1)

    # Lookup files
    results = []
    if os.path.isdir(args.FILE):
        if args.recursive:
            for r, d, f in os.walk(args.FILE):
                for file in f:
                    if args.verbose:
                        print("Analyzing {}".format(os.path.join(r, file)))
                    results += lookup(rules, os.path.join(r, file))
        else:
            for f in os.listdir(args.FILE):
                if os.path.isfile(os.path.join(args.FILE, f)):
                    if args.verbose:
                        print("Analyzing {}".format(os.path.join(args.FILE, f)))
                    results += lookup(rules, os.path.join(args.FILE, f))
    elif os.path.isfile(args.FILE):
        results += lookup(rules, args.FILE)

    for r in results:
        if r[1]:
            print("{} - MATCHES {}".format(
                r[0],
                ','.join(set(r[2]))
            ))
        else:
            if args.verbose:
                print("{} - NO DETECTION".format(r[0]))


def config():
    """
    Allows to configure default yara folders
    """
    parser = argparse.ArgumentParser()
    subparsers = parser.add_subparsers(help='Subcommand')
    parser_a = subparsers.add_parser('add', help='Add a Yara rule folder')
    parser_a.add_argument('FILE', help='Yara rule file')
    parser_a.set_defaults(command='add')
    parser_b = subparsers.add_parser('list', help='List exising Yara files')
    parser_b.set_defaults(command='list')
    parser_c = subparsers.add_parser('del', help='Remove a file from the list')
    parser_c.add_argument('FILE', help='Yara rule file')
    parser_c.set_defaults(command='del')
    parser_d = subparsers.add_parser('pull', help='Git pull folders that are git repositories')
    parser_d.set_defaults(command='pull')
    args = parser.parse_args()

    if 'command' in args:
        if args.command == 'list':
            if os.path.isfile(CONFIG_PATH):
                config = read_config()
                for f in config["files"]:
                    print(f)
            else:
                print("No config file, please add a first folder")
        elif args.command == "add":
            # Adding file to the list
            if not os.path.isfile(args.FILE):
                print("Invalid file")
                # TODO : check that the rule is valid
                sys.exit(1)
            config = read_config()
            if args.FILE in config['files']:
                print("File already in the list")
                sys.exit(1)
            config['files'].append(args.FILE)
            with open(CONFIG_PATH, "w") as f:
                f.write(yaml.dump(config))
            print("File added")
        elif args.command == "del":
            config = read_config()
            if args.FILE in config['files']:
                config['files'].remove(args.FILE)
                with open(CONFIG_PATH, "w") as f:
                    f.write(yaml.dump(config))
                print("File removed")
            else:
                print("This file is not in the list, sorry")
        elif args.command == "pull":
            config = read_config()
            if len(config['files']) == 0:
                print("No yara file in the list, please add one with yaraa-config")
                sys.exit(0)
            for f in config['files']:
                path = os.path.dirname(f)
                if os.path.isdir(os.path.join(path, '.git')):
                    print("Updating {}".format(path))
                    call(["git", "-C", path, "pull"])
                else:
                    print("{} - Not a git folder".format(path))
        else:
            parser.print_help()
    else:
        parser.print_help()
