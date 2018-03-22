import pgpy
from ansible.parsing.dataloader import DataLoader
from ansible.inventory.manager import InventoryManager


def read_message(file_to_read):
    message = pgpy.PGPMessage.from_file(file_to_read)
    dir(message)
    print(message.encrypters)
    
def parse_ansible(inventory_file):
    
    data_loader = DataLoader()
    inventory = InventoryManager(loader = data_loader,
                             sources=[inventory_file])

    print(inventory.get_groups_dict()['testgroup1'])

if __name__ == '__main__':
    read_message('/home/alisa/Downloads/test.pw.gpg')
    parse_ansible('/home/alisa/Downloads/inventory_test')