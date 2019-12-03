from modules.Logger import logger_init
from modules import configuration
import logging
import paramiko
import random
import re
import time
import argparse


SIO_configuration = configuration.SIOconfiguration()
IntegrationConfigInstance = configuration.Integration()

##############################################################
#                      Test variables                        #
UseTestVarsSwitch = False
TestVars = {
    'list_servers': ['10.139.216.208', '10.139.216.205'],  # should contain at least 1 MDM
    'volume_name': 'vol_0cMaH2',
    'sds_ip': '10.139.216.205',
    'sds_device_path': '/dev/sdb',  # or '/dev/mapper/fake_sdb' in case of DM setup based devices
    'blocks_number': 1,
    'sdc_ip': '10.139.216.205',
    'data_interface_name': 'p2p1'
}
#                                                            #
##############################################################

if UseTestVarsSwitch is True:
    log_level = "DEBUG"
    log_to_file = False
    list_servers = TestVars['list_servers']
    sds_ip = TestVars['sds_ip']
    sdc_ip = TestVars['sdc_ip']
    volume_name = TestVars['volume_name']
    sds_device_path = TestVars['sds_device_path']
    blocks_number = TestVars['blocks_number']
    data_interface_name = TestVars['data_interface_name']
else:
    parser = argparse.ArgumentParser(description='Returns a list of scini offset '
                                                 '<-> physical block offset for a specific device')
    ##################################################################
    parser.add_argument("--mdm_server_ips", type=str)
    parser.add_argument("--volume_name", type=str)
    parser.add_argument("--sds_ip", type=str)
    parser.add_argument("--sds_device_path", type=str)
    parser.add_argument("--sdc_ip", type=str)
    parser.add_argument("--blocks_number", type=int, default=1)
    parser.add_argument("--data_interface_name", type=str, default="p2p1")
    ##################################################################
    parser.add_argument("-ll", "--log_level", type=str, default='INFO')
    parser.add_argument('-lf', "--log_to_file", type=bool, default=False)
    ##################################################################
    args = parser.parse_args()
    if None in [args.mdm_server_ips, args.volume_name, args.sds_ip, args.sds_device_path]:
        print('ERROR: Not all needed arguments were provided')
        parser.print_help()
        exit(1)

    list_servers = str(args.mdm_server_ips).split(',')
    sds_ip = args.sds_ip
    if args.sdc_ip is not None:
        sdc_ip = args.sdc_ip
    else:
        sdc_ip = args.sds_ip
    volume_name = args.volume_name
    sds_device_path = args.sds_device_path
    blocks_number = args.blocks_number
    data_interface_name = args.data_interface_name
    log_level = args.log_level
    log_to_file = args.log_to_file

MainLogger = logger_init.logging_config(integration_config=IntegrationConfigInstance, logging_mode=log_level,
                                        log_to_file=log_to_file, executable_path=__file__)

MainLogger.info('Starting the main process')
mdm_connection_postfix = '--mdm_ip '
DO_DIT_ADD = True
for each_server in list_servers:
    mdm_connection_postfix += each_server + ','
mdm_connection_postfix = mdm_connection_postfix[:-1]

MainLogger.info('Establishing connection to all needed servers')
if sdc_ip not in list_servers:
    list_servers.append(sdc_ip)
if sds_ip not in list_servers:
    list_servers.append(sds_ip)
connections_dict = {}
for each_server in list_servers:
    ssh = paramiko.SSHClient()
    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    ssh.connect(each_server, username=SIO_configuration.server_user, password=SIO_configuration.server_password)
    connections_dict.update({
        each_server: ssh
    })


# getting info about installed system to locate volume, sds and sds_device IDs


def invoke_ssh_commands(list_servers_func: list, connections_dict_func: dict, commands: tuple):
    def _execute_command_on_server_no_stdout(ssh_handler, command):
        logger_inst_func = logging.getLogger()
        ssh_stdin, ssh_stdout, ssh_stderr = ssh_handler.exec_command(command)
        result = str(ssh_stderr.read().decode('ascii').rstrip())
        if len(result) > 0:
            logger_inst_func.debug(result)
            if result.startswith('Error: MDM failed command.  Status: The volume is already mapped to this SDC'):
                pass
            else:
                raise Exception
        else:
            pass

    def _execute_command_on_server(ssh_handler, command):
        logger_inst_func = logging.getLogger()
        ssh_stdin, ssh_stdout, ssh_stderr = ssh_handler.exec_command(command)
        result = str(ssh_stdout.read().decode('ascii').rstrip())
        if len(result) > 0:
            logger_inst_func.debug(result)
            final_result = result.splitlines()
            '''
            if len(final_result) == 1: 
                final_result = final_result[0]
            '''
            return final_result
        else:
            error = ssh_stderr.read().decode('ascii').rstrip()
            if len(error) > 0:
                logger_inst_func.debug(error)
            else:
                logger_inst_func.debug("Zero ssh_stdout, Zero ssh_stderr")
            raise Exception

    cumulative_result = []
    logger_inst = logging.getLogger()
    # logger_inst.debug('Startup attr: {}, {}, {}'.format(list_servers_func, connections_dict_func, commands))
    for each_server_func in list_servers_func:
        ssh_func = connections_dict_func[each_server_func]
        for each_command_tuple in commands:
            logger_inst.debug('Executing a command "{}" on {}'.format(each_command_tuple[1], each_server_func))
            if each_command_tuple[0] is False:
                _execute_command_on_server_no_stdout(ssh_func, each_command_tuple[1])
                cumulative_result.append((each_server_func, each_command_tuple[1], 'NULL'))
            else:
                result = _execute_command_on_server(ssh_func, each_command_tuple[1])
                cumulative_result.append((each_server_func, each_command_tuple[1], result))
    return cumulative_result


MainLogger.info('Stage 0: Checking requirements: '
                '1. SDC is visible on mdm')

commands_to_execute = ((True, 'ip -f inet addr show ' + data_interface_name + ' | grep -Po \'inet \K[\d.]+\''),)
stage_result = invoke_ssh_commands(list_servers_func=[sdc_ip],
                                   connections_dict_func=connections_dict,
                                   commands=commands_to_execute)
target_sdc_data_ip_nic = stage_result[0][2][0]

commands_to_execute = (
(False, 'scli --login --username {} --password {} {} --approve_certificate'.format(SIO_configuration.admin_username,
                                                                                   SIO_configuration.admin_password,
                                                                                   mdm_connection_postfix)),
(True, 'scli --query_all_sdc {} | grep "IP: {}"'.format(mdm_connection_postfix,
                                                        target_sdc_data_ip_nic)
 + '| awk \'{print $3}\''))
try:
    stage_result = invoke_ssh_commands(list_servers_func=[list_servers[0]],
                                       connections_dict_func=connections_dict,
                                       commands=commands_to_execute)
except Exception as error:
    MainLogger.debug('error')
    MainLogger.error('Unable to validate SDC is connected to a SIO system - please, check requirements')
    exit(0)
target_sdc_id = stage_result[1][2][0]

MainLogger.debug('Stage 0 results: {}'.format(str(stage_result)))

MainLogger.info('Stage 1: enabling DIT')

# stage 1a - checking if DIT was already enabled

commands_to_execute = ((True, 'cat /opt/emc/scaleio/sds/cfg/conf.txt'),)

stage_result = invoke_ssh_commands(list_servers_func=[sds_ip],
                                   connections_dict_func=connections_dict,
                                   commands=commands_to_execute)

if 'trc_compressed_file_enabled=1' in stage_result[0][2]:
    MainLogger.info('trc_compressed_file_enabled is manually set to ON, removing this lines')
    COMP_DIT_ON_in_conf_file = True
else:
    COMP_DIT_ON_in_conf_file = False

if 'trc_compressed_file_enabled=0' not in stage_result[0][2]:
    MainLogger.info('trc_compressed_file_enabled is not set to OFF, adding it to hit v3.5')
    COMP_DIT_add_to_conf_file = True
else:
    COMP_DIT_add_to_conf_file = False

if 'tgt_dit__extra_enabled=0' in stage_result[0][2] or 'tgt_dit__enabled=0' in stage_result[0][2]:
    MainLogger.info('DIT is manually set to OFF, removing this lines')
    DIT_OFF_in_conf_file = True
else:
    DIT_OFF_in_conf_file = False
if 'tgt_dit__extra_enabled=1' in stage_result[0][2] and 'tgt_dit__enabled=1' in stage_result[0][2]:
    MainLogger.info('Seems like DIT is already ON, skipping step')
    DIT_ON_in_conf_file = True
else:
    DIT_ON_in_conf_file = False

if COMP_DIT_ON_in_conf_file:
    commands_to_execute = ((False,
                            "sed -n '/trc_compressed_file_enabled=1/!p' /opt/emc/scaleio/sds/cfg/conf.txt > /opt/emc/scaleio/sds/cfg/conf_temp.txt"),
                           (False,
                            "mv /opt/emc/scaleio/sds/cfg/conf.txt /opt/emc/scaleio/sds/cfg/conf_old.txt && mv /opt/emc/scaleio/sds/cfg/conf_temp.txt /opt/emc/scaleio/sds/cfg/conf.txt && rm /opt/emc/scaleio/sds/cfg/conf_temp.txt -f"),
                           (False, 'pkill sds'))
    stage_result = invoke_ssh_commands(list_servers_func=[sds_ip],
                                       connections_dict_func=connections_dict,
                                       commands=commands_to_execute)
    MainLogger.info('trc_compressed_file_enabled=1 was removed from the conf file')

if DIT_OFF_in_conf_file:
    commands_to_execute = ((False,
                            "sed -n '/tgt_dit__extra_enabled=0/!p' /opt/emc/scaleio/sds/cfg/conf.txt > /opt/emc/scaleio/sds/cfg/conf_temp.txt"),
                           (False,
                            "mv /opt/emc/scaleio/sds/cfg/conf.txt /opt/emc/scaleio/sds/cfg/conf_old.txt && mv /opt/emc/scaleio/sds/cfg/conf_temp.txt /opt/emc/scaleio/sds/cfg/conf.txt && rm /opt/emc/scaleio/sds/cfg/conf_temp.txt -f"),
                           (False,
                            "sed -n '/tgt_dit__enabled=0/!p' /opt/emc/scaleio/sds/cfg/conf.txt > /opt/emc/scaleio/sds/cfg/conf_temp.txt"),
                           (False,
                            "mv /opt/emc/scaleio/sds/cfg/conf.txt /opt/emc/scaleio/sds/cfg/conf_old.txt && mv /opt/emc/scaleio/sds/cfg/conf_temp.txt /opt/emc/scaleio/sds/cfg/conf.txt && rm /opt/emc/scaleio/sds/cfg/conf_temp.txt -f"),
                           (False, 'pkill sds'))
    stage_result = invoke_ssh_commands(list_servers_func=[sds_ip],
                                       connections_dict_func=connections_dict,
                                       commands=commands_to_execute)
    MainLogger.info('tgt_dit__extra_enabled=0 and tgt_dit__enabled=0 were removed from the conf file')

if COMP_DIT_add_to_conf_file:
    commands_to_execute = ((False, 'echo "trc_compressed_file_enabled=0">>/opt/emc/scaleio/sds/cfg/conf.txt'),
                           (False, 'pkill sds'))
    stage_result = invoke_ssh_commands(list_servers_func=[sds_ip],
                                       connections_dict_func=connections_dict,
                                       commands=commands_to_execute)
    MainLogger.info('trc_compressed_file_enabled=0 was added to the conf file')

if not DIT_ON_in_conf_file:
    commands_to_execute = ((False, 'echo "tgt_dit__enabled=1">>/opt/emc/scaleio/sds/cfg/conf.txt'),
                           (False, 'echo "tgt_dit__extra_enabled=1">>/opt/emc/scaleio/sds/cfg/conf.txt'),
                           (False, 'pkill sds'))
    stage_result = invoke_ssh_commands(list_servers_func=[sds_ip],
                                       connections_dict_func=connections_dict,
                                       commands=commands_to_execute)
    MainLogger.debug('Stage 1 results: {}'.format(str(stage_result)))
else:
    MainLogger.info('Stage 1 results: DIT add disabled')

MainLogger.info('Stage 2: Getting DATA IPs to locate SDSes over SCLI')
commands_to_execute = ((True, 'ip -f inet addr show ' + data_interface_name + ' | grep -Po \'inet \K[\d.]+\''),)
stage_result = invoke_ssh_commands(list_servers_func=list_servers,
                                   connections_dict_func=connections_dict,
                                   commands=commands_to_execute)
data_interface_ip_dict = dict()
for each_result_tuple in stage_result:
    data_interface_ip_dict.update({each_result_tuple[0]: each_result_tuple[2][0]})
MainLogger.debug('Stage 2 results: {}'.format(str(stage_result)))

MainLogger.info('Stage 3: Getting Volume ID, SDS ID')
target_sds_data_ip = data_interface_ip_dict[sds_ip]

commands_to_execute = (
(False, 'scli --login --username {} --password {} {} --approve_certificate'.format(SIO_configuration.admin_username,
                                                                                   SIO_configuration.admin_password,
                                                                                   mdm_connection_postfix)),
(True, 'scli --query_all_volumes {} | grep "Name: {}"  '.format(mdm_connection_postfix,
                                                                volume_name)
 + '| awk \'{print $3}\''),
(True, 'scli --query_all_sds {} | grep "Joined IP: {}"'.format(mdm_connection_postfix,
                                                               target_sds_data_ip)
 + '| awk \'{print $3}\''))
try:
    stage_result = invoke_ssh_commands(list_servers_func=[list_servers[0]],
                                       connections_dict_func=connections_dict,
                                       commands=commands_to_execute)
except Exception as error:
    MainLogger.error(
        "Unable to grep a volumeID by name {} or SDC ID by IP {} - check input and try again".format(volume_name,
                                                                                                     target_sds_data_ip))
    exit(1)

target_volume_id = stage_result[1][2][0]
target_sds_id = stage_result[2][2][0]
MainLogger.debug('Stage 3 results: {}'.format(str(stage_result)))

MainLogger.info('Stage 4: Getting target SDS device ID')
commands_to_execute = (
(False, 'scli --login --username {} --password {} {} --approve_certificate'.format(SIO_configuration.admin_username,
                                                                                   SIO_configuration.admin_password,
                                                                                   mdm_connection_postfix)),
(True, 'scli --query_sds --sds_id {} {} | grep {}'.format(target_sds_id,
                                                          mdm_connection_postfix,
                                                          sds_device_path)
 + '| awk \'{print $9}\''))
try:
    stage_result = invoke_ssh_commands(list_servers_func=[list_servers[0]],
                                       connections_dict_func=connections_dict,
                                       commands=commands_to_execute)
except Exception as error:
    MainLogger.error(
        "Unable to grep a device ID from SDS devices by path {} on SDC with ID {} - check input and try again".format(
            sds_device_path,
            target_sds_id))
    exit(1)
target_device_id = stage_result[1][2][0]
MainLogger.debug('Stage 4 results: {}'.format(str(stage_result)))

MainLogger.info(
    'Stage 5: Dumping v2d and getting tgt volume "offsets-disk comb-comb offset" info regarding the tgt disk')
commands_to_execute = (
(False, 'scli --login --username {} --password {} {} --approve_certificate'.format(SIO_configuration.admin_username,
                                                                                   SIO_configuration.admin_password,
                                                                                   mdm_connection_postfix)),
(False, 'scli --debug_action --vol_offsets_dump --filename /tmp/v2d --object_id {} {}'.format(target_volume_id,
                                                                                              mdm_connection_postfix)),
(True, 'less /tmp/v2d | grep {}'.format(target_device_id) + ' | awk \'{print $3,$11,$17}\'')
)
stage_result = invoke_ssh_commands(list_servers_func=[list_servers[0]],
                                   connections_dict_func=connections_dict,
                                   commands=commands_to_execute)
volumeoff_comb_comboff = stage_result[2][2]
MainLogger.debug('Stage 5 results: {}'.format(str(stage_result)))

MainLogger.info('Stage 6: Locate scini device to write IO on SDC')
commands_to_execute = (
(False, 'scli --login --username {} --password {} {} --approve_certificate'.format(SIO_configuration.admin_username,
                                                                                   SIO_configuration.admin_password,
                                                                                   mdm_connection_postfix)),
(False, 'scli --map_volume_to_sdc --sdc_id {}  --volume_id {} --allow_multi_map {}'.format(target_sdc_id,
                                                                                           target_volume_id,
                                                                                           mdm_connection_postfix))
)

invoke_ssh_commands(list_servers_func=[list_servers[0]],
                    connections_dict_func=connections_dict,
                    commands=commands_to_execute)

commands_to_execute = ((True, 'ls -l /dev/disk/by-id/ | grep {} '.format(target_volume_id) + "| awk '{print $11}'"),
                       )
stage_result = invoke_ssh_commands(list_servers_func=[sdc_ip],
                                   connections_dict_func=connections_dict,
                                   commands=commands_to_execute)
target_scini_path = '/dev/' + stage_result[0][2][0].replace('../../', '')
MainLogger.debug('Stage 6 results: {}'.format(str(stage_result)))

MainLogger.info('Stage 7: Writing blocks on target to grasp phys location on disk {}'.format(target_scini_path))

scini_volume_to_dev_offesets_map = dict()
for block in range(0, blocks_number):
    random_block = random.randint(0, len(volumeoff_comb_comboff))
    selected_block = volumeoff_comb_comboff[random_block]
    selected_block_scini_offset, selected_block_comb, selected_block_offset_in_comb = selected_block.split(' ')
    scini_volume_to_dev_offesets_map.update({
        selected_block_scini_offset: {'offset_in_comb': selected_block_offset_in_comb,
                                      'comb_id': selected_block_comb,
                                      'offset_on_actual_disk': None}
    })

MainLogger.debug('scini_volume_to_dev_offesets_map BEFORE actual disk offsets were located: {}'.format(
    scini_volume_to_dev_offesets_map))

# fio --name=f_thread --ioengine=libaio --rw=write --bs=1024k --direct=1 --size=1M --numjobs=1 --thread --rwmixread=80
#  --filename=/dev/scinia  --offset=1099511627776
for each_block_offset, offset_props in scini_volume_to_dev_offesets_map.items():
    MainLogger.debug('Writing into {} offset on device {} '.format(each_block_offset, target_scini_path))

    commands_to_execute = ((False, 'fio --name=f_thread --ioengine=libaio --rw=write --bs=1024k --direct=1 --size=1M '
                                   '--numjobs=1 --thread --rwmixread=80 --filename={}  --offset={}M'.format(
        target_scini_path, each_block_offset)),)
    invoke_ssh_commands(list_servers_func=[sdc_ip],
                        connections_dict_func=connections_dict,
                        commands=commands_to_execute)
    commands_to_execute = (
    (True, 'cat /opt/emc/scaleio/sds/logs/trc.0 | grep ") ({} {}) (2048" | head -1'.format(offset_props['comb_id'],
                                                                                           offset_props[
                                                                                               'offset_in_comb'])),)
    # sometimes we ask quicker than SDS writes into log
    time.sleep(2)
    try:
        stage_result = invoke_ssh_commands(list_servers_func=[sds_ip],
                                           connections_dict_func=connections_dict,
                                           commands=commands_to_execute)
    except Exception as error:
        MainLogger.error("Unable to grep IO related records from trc.0 - check input\DIT and try again".format(
            volume_name, target_sds_data_ip))
        pass

    regex = r": Write to disk \(" + sds_device_path.replace('/', '\/') + "\s(\d*)\)\s\(" + offset_props[
        'comb_id'] + " " + offset_props['offset_in_comb'] + "\)"
    match = re.search(regex, stage_result[0][2][0])
    if match:
        scini_volume_to_dev_offesets_map[each_block_offset]['offset_on_actual_disk'] = match.group(1)
    else:
        scini_volume_to_dev_offesets_map[each_block_offset]['offset_on_actual_disk'] = False

MainLogger.info('Result: ' + str(scini_volume_to_dev_offesets_map))
