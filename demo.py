from upper_computer_SW.methods import Aes128Util, crc16_calc, deal_data
dict_up_frame = {
        'frame_head': [2, 'A568'],
        'frame_length': [2],    #帧长度，从头到尾
        'frame_no': [2],
        'protocol_num': [1, '02'],
        'manufacturer_num': [1, '1B'],
        'device_type': [1, '02'],
        'IMEI': [15],
        'RSRP': [2],    #参考信号接收功率
        'SNR': [2],     #信噪比
        'ECL': [1],     #信号覆盖等级，0、1、2
        'CSQ': [1],     #信号质量
        'fuc_code': [1],
        'encrypted_identity': [1],  #加密标识，0-不加密，1-加密
        'data_length': [2], #
        'data': [],
        'CRC16': [2],
        'frame_tail': [1, '16']
    }


def analysis_frame_head(string):
    frame_head = dict_up_frame['frame_head'][1]
    if string == frame_head:
        result = '帧起始符正确:' + frame_head
    else:
        result = '帧起始符错误:' + string
    print(result)
    return result


# 解析帧长度，传入整个帧
def analysis_frame_length(list_data):
    frame_length = list_data[3] + list_data[2]  # 原帧长度，转成小端
    list_length = deal_data.get_data_length(len(list_data))
    if len(list_length) < 4:
        temp = 4 - len(list_length)
        list_length = '0'*temp + list_length
    if list_length == frame_length:
        result = '帧长度正确:' + frame_length
    else:
        result = '帧长度错误:' + frame_length
    print(result)
    return result


def analysis_frame_no(string):
    result = '帧序号:' + string
    print(result)
    return result


def analysis_protocol_num(string):
    protocol_num = dict_up_frame['protocol_num'][1]
    if string == protocol_num:
        result = '协议版本号正确:' + protocol_num
    else:
        result = '协议版本号错误:' + string
    print(result)
    return result


def analysis_manufacturer_num(string):
    manufacturer_num = dict_up_frame['manufacturer_num'][1]
    if string == manufacturer_num:
        result = '厂家编码正确:' + manufacturer_num
    else:
        result = '厂家编码错误:' + string
    print(result)
    return result


def analysis_device_type(string):
    device_type = dict_up_frame['device_type'][1]
    if string == device_type:
        result = '设备类型正确:' + device_type
    else:
        result = '设备类型错误:' + string
    print(result)
    return result


def analysis_IMEI(string):
    IMEI = string[1::2]
    result = 'IMEI:' + IMEI
    print(result)
    return result


def analysis_RSRP(string):
    RSRP = str(int(string, 16) - 65536)
    result = 'RSRP:' + RSRP
    print(result)
    return result


def analysis_SNR(string):
    SNR = str(int(string, 16))
    result = 'SNR:' + SNR
    print(result)
    return result


def analysis_ECL(string):
    # string = '0x' + string
    print(string)
    result = 'ECL:' + string
    print(result)
    return result


def analysis_CSQ(string):
    result = 'CSQ:' + str(int('0x'+string, 16))
    print(result)
    return result


def analysis_fuc_code(string):
    fuc_code = string
    if fuc_code == '81':
        result = '参数设置应答'
    elif fuc_code == '02':
        result = '数据上报'
    elif fuc_code == '83':
        result = '信息查询应答'
    elif fuc_code == '84':
        result = '数据透传应答'
    elif fuc_code == '05':
        result = '数据补报'
    elif fuc_code == '86':
        result = '读取历史数据应答'
    else:
        result = '错误'
    result = '功能码:' + result
    print(result)
    return result


# 加密标识
def analysis_encrypted_identity(string):
    encrypted_identity = string
    if encrypted_identity == '00':
        result = '不加密'
    else:
        result = '加密'
    result = '加密标识:' + result
    return result


# 数据域
def analysis_aes_128(string):
    result = []
    result.append('数据域: ')
    data = Aes128Util.decrypt_data(string).upper()
    # result.append(data)
    result_data_length = data_length(data)
    result.append(result_data_length[0])
    tag_1 = data[4:6]
    tag_1_length_string = data[8] + data[9] + data[6] + data[7]
    tag_1_length = int(tag_1_length_string, 16) # 第一个tag长度
    temp = 10 + tag_1_length * 2
    tag_1_data = data[10:temp+1]


    return result


def analysis_crc16(list_data):
    data = ''
    temp_crc = list_data[-2]+ list_data[-3]
    temp = list_data[:-3]   # 取CRC前的全部数据
    for item in temp:
        data += item
    crc = crc16_calc.calc_crc(data).upper()
    crc_2 = crc[2] + crc[3] + crc[0] + crc[1]
    if temp_crc == crc_2:
        result = "CRC校验正确:" + crc
    else:
        result = "CRC校验错误:" + temp_crc
    print(result)
    return result


def anaylsis_frame_tail(string):
    frame_tail = dict_up_frame['frame_tail'][1]
    if string == frame_tail:
        result = '帧结束符正确:' + frame_tail
    else:
        result = '帧结束符错误:' + string
    print(result)
    return result


def analysis_data(data):
    list_data = deal_data.deal_data(data)
    IMEI = ''
    DF = ''
    frame_head = list_data[0] + list_data[1]
    frame_no = list_data[4] + list_data[5]
    protocol_num = list_data[6]
    manufacturer_num = list_data[7]
    device_type = list_data[8]
    for item in list_data[9:24]:
        IMEI += item
    RSRP = list_data[25] + list_data[24]
    SNR = list_data[27] + list_data[26]
    ECL = list_data[28]
    CSQ = list_data[29]
    fuc_code = list_data[30]
    encrypted_identity = list_data[31]
    for item in list_data[32:-3]:
        DF += item
    frame_tail = list_data[-1]
    list_result = []
    list_result.append(analysis_frame_head(frame_head))
    list_result.append(analysis_frame_length(list_data))
    list_result.append(analysis_frame_no(frame_no))
    list_result.append(analysis_protocol_num(protocol_num))
    list_result.append(analysis_manufacturer_num(manufacturer_num))
    list_result.append(analysis_device_type(device_type))
    list_result.append(analysis_IMEI(IMEI))
    list_result.append(analysis_RSRP(RSRP))
    list_result.append(analysis_SNR(SNR))
    list_result.append(analysis_ECL(ECL))
    list_result.append(analysis_CSQ(CSQ))
    list_result.append(analysis_fuc_code(fuc_code))
    list_result.append(analysis_encrypted_identity(encrypted_identity))
    aes_result = analysis_aes_128(DF)
    for item in aes_result:
        list_result.append(item)
    list_result.append(analysis_crc16(list_data))
    list_result.append(anaylsis_frame_tail(frame_tail))
    list_result.append('\n-----------------------\n')
    return list_result


def data_length(data):
    result = []
    data_length_hex = data[2] + data[3] + data[0] + data[1]
    data_length_int = int(data_length_hex, 16)  # 数据域长度
    real_lenth = (len(data) - 4) / 2
    if (data_length_int != real_lenth):
        result.append('数据域长度错误！')
    else:
        result.append("数据域长度为：" + str(real_lenth))  #result集第一个元素为输出值
    result.append(data_length_int)  #result集第二个元素为数据域长度
    return result


# tag解析
def data_tag(data):
    data_tag_result = []
    tag_no = data[4:6]
    tag_1_length_string = data[8] + data[9] + data[6] + data[7]
    tag_1_length = int(tag_1_length_string, 16) # 第一个tag长度
    temp = 10 + tag_1_length * 2
    tag_1_data = data[10:temp+1]
    # tag_no = data[4:6]
    # tag_length = data[6] + 
    if tag_no == '02':
        tag = 'Tag02：结果码'
        
        if tag_1_length != 1:

            result.append()
    elif tag_no == '03':
        tag = 'Tag03:基础信息'

    elif tag_no == '04':
        tag = 'Tag04:终端参数'

    elif tag_no == '05':
        tag = 'Tag05:报警数据'

    elif tag_no == '07':
        tag = 'Tag07:水表实时数据'

    data_tag_result.append(tag)

# 基础信息tag
TAG_03 = {
    '00' : ['ICCID', 20]
    '01' : ['设备类型', 1],
    '02' : ['水表表号', 7],
    '03' : ['终端时钟', 6],
    '04' : ['终端软件版本', 1]
}


# 终端参数tag
TAG_04 = {
    '00' : ['过流告警阈值', 4],
    '01' : ['持续过流告警时间', 1],
    '02' : ['返流告警阈值', 4],
    '03' : ['持续反流告警时间', 1],
    '04' : ['电压告警阈值', 2],
    '05' : ['服务器地址', 32],
    '06' : ['APN信息', 32],
    '07' : ['上报重连次数', 1],
    '08' : ['周期上报离散起始时间+结束时间+离散估长', 13],
    '09' : ['终端起停设置', 1],
    '0A' : ['周期上报频率', 1],
    '0B' : ['密集上报采样起始时间', 1],
    '0C' : ['周期采样间隔', 1],
    '14' : ['上报重连等待时间', 1],
    '15' : ['密集采样间隔', 1],
    '16' : ['KEY', 16],
}


# 告警数据tag
TAG_05 = {
    '00' : ['', ],
    '01' : ['', ],
    '02' : ['', ],
    '03' : ['', ],
    '' : ['', ],
    '' : ['', ],
    '' : ['', ],

}
# while(True):
#     DATA = input('数据：')
#     print("-------------------------------------------------")
#     analysis_data(DATA)
#     print("-------------------------------------------------")
# DATA ='A568E3000000021B02383634383331303534373936343135A7FF1400000E0201C9E0013EFF87DEC41B8E24A90CA244ACB072A6991E61B9551E92C7317BCB09E32F4081D8BA25B2276FFEF72E0482DD7AC2DBEFDC0BA643FC0C6FF92FBF839F183E275ED37BC74656F0F1201B166175F93E275ED37BC74656F0F1201B166175F93E275ED37BC74656F0F1201B166175F93E275ED37BC74656F0F1201B166175F93E275ED37BC74656F0F1201B166175F991A81FE6488CF2F0D9DB4FD83FC90B351CCD9D90CEE185C97516FFCBE415922B5E5A4FF0D0A9352A72D45FCFC9FE0E20564316'
# analysis_data(DATA)