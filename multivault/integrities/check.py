import pgpy
from ansible.parsing.dataloader import DataLoader
from ansible.inventory.manager import InventoryManager

import ansible.playbook.play as play
import yaml
from multivault.utilities import util_crypt

INVENTORY_FILE = '/home/alisa/git/playbooks/inventory.ini'
IGNORED = ['ubuntu', 'debian', 'ubuntu_host', 'debian_host']
INVENTORY = InventoryManager(loader=DataLoader(),
                             sources=[INVENTORY_FILE])


def read_message(file_to_read):
    message = pgpy.PGPMessage.from_file(file_to_read)
    dir(message)
    print(message.encrypters)



def parse_play(play_file):

    with open(play_file, mode = "r") as playbook:
        playbook=yaml.load(playbook)
       # print(playbook)
        for task in playbook:
            # print(task["hosts"])
            hosts=task['hosts'].lower().split(',')
            hosts=[host.strip() for host in hosts]
            div=set(hosts)-set(IGNORED)
            div=list(div)
            print(match(div))
def match(groups):
    hosts = []
    for group in groups :
        if group.startswith('!'):
            pass
        else :
            try:
                hosts.append(INVENTORY.get_groups_dict()[group])
            except Exception:
                pass
    
    return util_crypt.flatten(hosts)
    



if __name__ == '__main__':
    read_message('/home/alisa/Downloads/test.pw.gpg')
    parse_play('/home/alisa/git/playbooks/all.yml')
