# -*- coding: utf-8 -*-

import socket
import random
import time
import argparse

class Colors:
	BLUE 		= '\033[94m'
	GREEN 		= '\033[32m'
	RED 		= '\033[0;31m'
	DEFAULT		= '\033[0m'
	ORANGE 		= '\033[33m'
	WHITE 		= '\033[97m'
	BOLD 		= '\033[1m'
	BR_COLOUR 	= '\033[1;37;40m'
	CYELLOWBG2  = '\033[103m'
	CYELLOW 	= '\033[33m'
	CVIOLETBG 	= '\033[45m'
	CGREENBG  	= '\033[42m'




banner = r'''
	 __  __           _ _                 _____                 _   _                 
	|  \/  | ___   __| | |__  _   _ ___  |  ___|   _ _ __   ___| |_(_) ___  _ __  ___ 
	| |\/| |/ _ \ / _` | '_ \| | | / __| | |_ | | | | '_ \ / __| __| |/ _ \| '_ \/ __|
	| |  | | (_) | (_| | |_) | |_| \__ \ |  _|| |_| | | | | (__| |_| | (_) | | | \__ \
	|_|  |_|\___/ \__,_|_.__/ \__,_|___/ |_|   \__,_|_| |_|\___|\__|_|\___/|_| |_|___/


	# Industrial Army ( by Dreamlab Technologies )	

'''

parser = argparse.ArgumentParser(prog='modbus_functions.py',
								description=' [+] Recognition of implemented "MODBUS" functions.', 
								epilog='[+] Demo: modbus_functions.py <modbus host>',
								version="1.0")

parser.add_argument('--sid', 	dest="SID",  help='Slave ID', default=0)
parser.add_argument('--host', 	dest="HOST",  help='Host',required=True)
parser.add_argument('--port', 	dest="PORT",  help='Port',type=int,default=502)

parser.add_argument('-vb',	 	dest="VERBOSE",  help='Verbose mode',default='0',choices=['1','0'])
#parser.add_argument('--pdu_data', 	dest="pdu_data",  help='',default="01ff000000000000")
#parser.add_argument('--delay', 	dest="Req delay ",  help='',type=int,default=.5)


args        	= 	parser.parse_args()

HST   			= 	args.HOST
SID 			= 	str(args.SID)
portModbus		= 	args.PORT
verboseMode		= 	args.VERBOSE



default_max_function = 128


print Colors.ORANGE+banner+Colors.DEFAULT

_modbus_exceptions = {  
					00: "** [00] **",								# ???
					01: "Illegal function",							# Funcion no implementada
					02: "Illegal data address",		   				# SID Incorrecto
					03: "Illegal data value",  						# Valor Incorrecto
					04: "Slave device failure",						# 
					05: "Acknowledge",  							# 
					06: "Slave device busy",  						# 
					07: "** [07] **", 								# 
					8: "Memory parity error",  					# 
					9: "** [09] **", 								#
					10: "Gateway path unavailable",					# 
					11: "Gateway target device failed to respond",	# 
					12: "** [12] **",	# 
					13: "** [13] **",	# 
					14: "** [14] **",	# 
					15: "** [15] **",	# 
					16: "** [16] **",	# 
					17: "** [17] **",	# 
					18: "** [18] **",	# 
					19: "** [19] **",	# 
					20: "** [20] **",	# 
					21: "** [21] **",	# 
					22: "** [22] **",	# 
					23: "** [23] **",	# 
					24: "** [24] **",	# 
					25: "** [25] **",	# 
					26: "** [26] **",	# 
					27: "** [27] **",	# 
					28: "** [28] **",	# 
					29: "** [29] **",	# 
					30: "** [30] **",	# 
					31: "** [31] **",	# 
					32: "** [32] **",	# 
					33: "** [33] **",	# 
					34: "** [34] **",	# 
					35: "** [35] **",	# 
					36: "** [36] **",	# 
					37: "** [37] **",	# 
					38: "** [38] **",	# 
					39: "** [39] **",	# 
					40: "** [40] **",	# 
					41: "** [41] **",	# 
					42: "** [42] **",	# 
					42: "** [42] **",	# 
					44: "** [44] **",	# 
					45: "** [45] **",	# 
					46: "** [46] **",	# 
					47: "** [47] **",	# 
					48: "** [48] **",	# 
					49: "** [49] **",	# 
					50: "** [50] **",	# 
					51: "** [51] **",	# 
					52: "** [52] **",	# 
					53: "** [53] **",	# 
					54: "** [54] **",	# 
					55: "** [55] **",	# 
					56: "** [56] **",	# 
					57: "** [57] **",	# 
					58: "** [58] **",	# 
					59: "** [59] **",	# 
					60: "** [60] **",	# 
					61: "** [61] **",	# 
					62: "** [62] **",	# 
					63: "** [63] **",	# 
					64: "** [64] **",	# 
					65: "** [65] **",	# 
					66: "** [66] **",	# 
					67: "** [67] **",	# 
					68: "** [68] **",	# 
					69: "** [69] **",	# 
					70: "** [70] **",	# 
					71: "** [71] **",	# 
					72: "** [72] **",	# 
					73: "** [73] **",	# 
					74: "** [74] **",	# 
					75: "** [75] **",	# 
					76: "** [76] **",	# 
					77: "** [77] **",	# 
					78: "** [78] **",	# 
					79: "** [79] **",	# 
					80: "** [80] **",	# 
					81: "** [81] **",	# 
					82: "** [82] **",	# 
					83: "** [83] **",	# 
					84: "** [84] **",	# 
					85: "** [85] **",	# 
					86: "** [86] **",	# 
					87: "** [87] **",	# 
					88: "** [88] **",	# 
					89: "** [89] **",	# 
					90: "** [90] **",	# 
					91: "** [91] **",	# 
					92: "** [92] **",	# 
					93: "** [93] **",	# 
					94: "** [94] **",	# 
					95: "** [95] **",	# 
					96: "** [96] **",	# 
					97: "** [97] **",	# 
					98: "** [98] **",	# 
					99: "** [99] **",	# 
					100: "** [100] **",	# 
					101: "** [101] **",	# 
					102: "** [102] **",	# 
					103: "** [103] **",	# 
					104: "** [104] **",	# 
					105: "** [105] **",	# 
					106: "** [106] **",	# 
					107: "** [107] **",	# 
					108: "** [108] **",	# 
					109: "** [109] **",	# 
					110: "** [110] **",	# 
					111: "** [111] **",	# 
					112: "** [112] **",	# 
					113: "** [113] **",	# 
					114: "** [114] **",	# 
					115: "** [115] **",	# 
					116: "** [116] **",	# 
					117: "** [117] **",	# 
					118: "** [118] **",	# 
					119: "** [119] **",	# 
					120: "** [120] **",	# 
					121: "** [121] **",	# 
					122: "** [122] **",	# 
					123: "** [123] **",	# 
					125: "** [125] **",	# 
					126: "** [126] **",	# 
					127: "** [127] **",	# 
					128: "** [128] **",	# 
					129: "** [129] **",	# 
					130: "** [130] **",	# 
					131: "** [131] **",	# 
					132: "** [132] **",	# 
					133: "** [133] **",	# 
					134: "** [134] **",	# 
					135: "** [135] **",	# 
					136: "** [136] **",	# 
					137: "** [137] **",	# 
					138: "** [138] **",	# 
					139: "** [139] **",	# 
					140: "** [140] **",	# 
					141: "** [141] **",	# 
					142: "** [142] **",	# 
					142: "** [142] **",	# 
					144: "** [144] **",	# 
					145: "** [145] **",	# 
					146: "** [146] **",	# 
					147: "** [147] **",	# 
					148: "** [148] **",	# 
					149: "** [149] **",	# 
					150: "** [150] **",	# 
					151: "** [151] **",	# 
					152: "** [152] **",	# 
					153: "** [153] **",	# 
					154: "** [154] **",	# 
					155: "** [155] **",	# 
					156: "** [156] **",	# 
					157: "** [157] **",	# 
					158: "** [158] **",	# 
					159: "** [159] **",	# 
					160: "** [160] **",	# 
					161: "** [161] **",	# 
					162: "** [162] **",	# 
					163: "** [163] **",	# 
					164: "** [164] **",	# 
					165: "** [165] **",	# 
					166: "** [166] **",	# 
					167: "** [167] **",	# 
					168: "** [168] **",	# 
					169: "** [169] **",	# 
					170: "** [170] **",	# 
					171: "** [171] **",	# 
					172: "** [172] **",	# 
					173: "** [173] **",	# 
					174: "** [174] **",	# 
					175: "** [175] **",	# 
					176: "** [176] **",	# 
					177: "** [177] **",	# 
					178: "** [178] **",	# 
					179: "** [179] **",	# 
					180: "** [180] **",	# 
					181: "** [181] **",	# 
					182: "** [182] **",	# 
					183: "** [183] **",	# 
					184: "** [184] **",	# 
					185: "** [185] **",	# 
					186: "** [186] **",	# 
					187: "** [187] **",	# 
					188: "** [188] **",	# 
					189: "** [189] **",	# 
					190: "** [190] **",	# 
					191: "** [191] **",	# 
					192: "** [192] **",	# 
					193: "** [193] **",	# 
					194: "** [194] **",	# 
					195: "** [195] **",	# 
					196: "** [196] **",	# 
					197: "** [197] **",	# 
					198: "** [198] **",	# 
					199: "** [199] **",	#  
					200: "** [200] **",	#  
					201: "** [201] **",	# 
					202: "** [202] **",	# 
					203: "** [203] **",	# 
					204: "** [204] **",	# 
					205: "** [205] **",	# 
					206: "** [206] **",	# 
					207: "** [207] **",	# 
					208: "** [208] **",	# 
					209: "** [209] **",	# 
					210: "** [210] **",	# 
					211: "** [211] **",	# 
					212: "** [212] **",	# 
					213: "** [213] **",	# 
					214: "** [214] **",	# 
					215: "** [215] **",	# 
					216: "** [216] **",	# 
					217: "** [217] **",	# 
					218: "** [218] **",	# 
					219: "** [219] **",	# 
					220: "** [220] **",	# 
					221: "** [221] **",	# 
					222: "** [222] **",	# 
					223: "** [223] **",	# 
					225: "** [225] **",	# 
					226: "** [226] **",	# 
					227: "** [227] **",	# 
					228: "** [228] **",	# 
					229: "** [229] **",	# 
					230: "** [230] **",	# 
					231: "** [231] **",	# 
					232: "** [232] **",	# 
					233: "** [233] **",	# 
					234: "** [234] **",	# 
					235: "** [235] **",	# 
					236: "** [236] **",	# 
					237: "** [237] **",	# 
					238: "** [238] **",	# 
					239: "** [239] **",	# 
					240: "** [240] **",	# 
					241: "** [241] **",	# 
					242: "** [242] **",	# 
					242: "** [242] **",	# 
					244: "** [244] **",	# 
					245: "** [245] **",	# 
					246: "** [246] **",	# 
					247: "** [247] **",	# 
					248: "** [248] **",	# 
					249: "** [249] **",	# 
					250: "** [250] **",	# 
					251: "** [251] **",	# 
					252: "** [252] **",	# 
					253: "** [253] **",	# 
					254: "** [254] **",	# 
					255: "** [255] **",	# 
					255: "** [255] **"
				}


_modbus_function = {
					"00": " ***** ", 								# 00
					"01": " Read Coils ", 							# 01
					"02": " Read Discrete Inputs ", 				# 02
					"03": " Read Holding Registers ", 				# 03
					"04": " Read Input Register ", 					# 04
					"05": " Write Single Coil ", 					# 05
					"06": " Write Single Register ", 				# 06
					"07": " Read Exception status ", 				# 07
					"08": " Diagnostic ", 							# 08
					"09": " ***** ", # 09
					"0a": " ***** ", # 10
					"0b": " Get Com event counter ", 				# 11
					"0c": " Get Com Event Log ", 					# 12
					"0d": " ***** ", # 13
					"0e": " ***** ", # 14
					"0f": " Write Multiple Coils ", 				# 15
					"10": " Write Multiple Registers ", 			# 16
					"11": " Report Server ID ", 					# 17
					"12": " ***** ", # 18
					"13": " ***** ", # 19
					"14": " Read File record ", 					# 20
					"15": " Write File record ", 					# 21
					"16": " Mask Write Register ", 					# 22
					"17": " Read/Write Multiple Registers", 		# 23
					"18": " Read FIFO queue ", 						# 24
					"19": " ***** ", # 25
					"1a": " ***** ", # 26
					"1b": " ***** ", # 27
					"1c": " ***** ", # 28
					"1d": " ***** ", # 29
					"1e": " ***** ", # 30
					"1f": " ***** ", # 31
					"20": " ***** ", # 32
					"21": " ***** ", # 33
					"22": " ***** ", # 34
					"23": " ***** ", # 35
					"24": " ***** ", # 36
					"25": " ***** ", # 37
					"26": " ***** ", # 38
					"27": " ***** ", # 39
					"28": " ***** ", # 40
					"29": " ***** ", # 41
					"2a": " ***** ", # 42
					"2b": " Read device Identification ", # 43
					"2c": " ***** ", # 44
					"2d": " ***** ", # 45
					"2e": " ***** ", # 46
					"2f": " ***** ", # 47
					"30": " ***** ", # 48
					"31": " ***** ", # 49
					"32": " ***** ", # 50
					"33": " ***** ", # 51
					"34": " ***** ", # 52
					"35": " ***** ", # 53
					"36": " ***** ", # 54
					"37": " ***** ", # 55
					"38": " ***** ", # 56
					"39": " ***** ", # 57
					"3a": " ***** ", # 58
					"3b": " ***** ", # 59
					"3c": " ***** ", # 60
					"3d": " ***** ", # 61
					"3e": " ***** ", # 62
					"3f": " ***** ", # 63
					"40": " ***** ", # 64
					"41": " ***** ", # 65
					"42": " ***** ", # 66
					"43": " ***** ", # 67
					"44": " ***** ", # 68
					"45": " ***** ", # 69
					"46": " ***** ", # 70
					"47": " ***** ", # 71
					"48": " ***** ", # 72
					"49": " ***** ", # 73
					"4a": " ***** ", # 74
					"4b": " ***** ", # 75
					"4c": " ***** ", # 76
					"4d": " ***** ", # 77
					"4e": " ***** ", # 78
					"4f": " ***** ", # 79
					"50": " ***** ", # 80
					"51": " ***** ", # 81
					"52": " ***** ", # 82
					"53": " ***** ", # 83
					"54": " ***** ", # 84
					"55": " ***** ", # 85
					"56": " ***** ", # 86
					"57": " ***** ", # 87
					"58": " ***** ", # 88
					"59": " ***** ", # 89
					"5a": " UMAS (Schneider Electric proprietary protocol)", # 90
					"5b": " ***** ", # 91
					"5c": " ***** ", # 92
					"5d": " ***** ", # 93
					"5e": " ***** ", # 94
					"5f": " ***** ", # 95
					"60": " ***** ", # 96
					"61": " ***** ", # 97
					"62": " ***** ", # 98
					"63": " ***** ", # 99
					"64": " ***** ", # 100
					"65": " ***** ", # 101
					"66": " ***** ", # 102
					"67": " ***** ", # 103
					"68": " ***** ", # 104
					"69": " ***** ", # 105
					"6a": " ***** ", # 106
					"6b": " ***** ", # 107
					"6c": " ***** ", # 108
					"6d": " ***** ", # 109
					"6e": " ***** ", # 110
					"6f": " ***** ", # 111
					"70": " ***** ", # 112
					"71": " ***** ", # 113
					"72": " ***** ", # 114
					"73": " ***** ", # 115
					"74": " ***** ", # 116
					"75": " ***** ", # 117
					"76": " ***** ", # 118
					"77": " ***** ", # 119
					"78": " ***** ", # 120
					"79": " ***** ", # 121
					"7a": " ***** ", # 122
					"7b": " ***** ", # 123
					"7c": " ***** ", # 124
					"7d": " ***** ", # 125
					"7e": " ***** ", # 126
					"7f": " ***** ", # 127
					"80": " ***** "  # 128
}

def intToHex(int):
    strX = hex(int)
    return str(strX)[2:].zfill(2)

def is_hex(s):
    hex_digits = set("0123456789abcdef")
    for char in s:
        if not (char in hex_digits):
            return False
    return True

def hexToInt(hx):
	if is_hex(hx):
		integer = int(hx,16)
		return integer
	else:
		msg = ' [!] hexToInt():  failure'
		return msg
		exit()

def byteToInt(hx):
	hx = hx.zfill(2)
	if is_hex(hx) and len(hx) == 2:
		integerByte = int(hx,16)
		return integerByte
	else:
		msg = ' [!] bad_hexa '
		return msg

# --MBAP 7 Bytes --------------------------------------------------------  #
# Return a string with the modbus header
def create_header_modbus(length,unit_id):
    trans_id = hex(random.randrange(0000,65535))[2:].zfill(4)
    proto_id = "0000"
    protoLen = length.zfill(4)
    unit_id = unit_id

    return trans_id + proto_id + protoLen + unit_id.zfill(2)


# Contruccion del ADU
def mb_adu(slaveID, inject_fnc):
	modbusRequest = 	create_header_modbus('9',slaveID) 	#
	modbusRequest +=	str(inject_fnc)						# [PDU] Function
	modbusRequest += 	"01ff00000000000000" 				# [PDU] PADDING 

	return modbusRequest


def is_valid_function(vld_fnc, is_function, is_exception, send_req, get_resp, dbg=verboseMode):
	
	
	#send_req[0:4] 		# Transaction ID
	#send_req[4:8] 		# Proto ID
	#send_req[8:12] 	# Length
	#send_req[12:14] 	# SlaveID
	# // PDU 
	#send_req[14:16]  	# Function Code 
	#send_req[16:18]  	# error  

	#get_resp[0:4] 		# Transaction ID
	#get_resp[4:8] 		# Proto ID
	#get_resp[8:12] 	# Length
	#get_resp[12:14] 	# SlaveID
	# // PDU 
	#get_resp[14:16]  	# Function Code 
	#get_resp[16:18]  	# error  

	clr_req 	= Colors.RED + send_req[0:8]+Colors.BLUE + send_req[8:12]+Colors.ORANGE+send_req[12:14]+Colors.CVIOLETBG+send_req[14:16]+Colors.RED+send_req[16:]  +Colors.DEFAULT
	clr_resp 	= Colors.RED + get_resp[0:8]+Colors.BLUE + get_resp[8:12]+Colors.ORANGE+get_resp[12:14]+Colors.CVIOLETBG+get_resp[14:16]+Colors.DEFAULT+Colors.GREEN+get_resp[16:18] +Colors.RED+get_resp[18:] +Colors.DEFAULT

	exception_code = (get_resp[16:18].zfill(2))

	#print " [dbg] ERROR_CODE: "+str(exception_code)
	error_code = hexToInt(exception_code)
	info_error 	= Colors.BLUE + "\"" +str(_modbus_exceptions[error_code]) + "\"" + Colors.DEFAULT


	funcion_modbus = int(vld_fnc)
	fnc_error = (int(byteToInt(is_function)) - 128 )

	if (funcion_modbus == fnc_error):

	
		if str(is_exception) != '01':
			print Colors.GREEN+" [+] Valid Function :"+Colors.BLUE+str(vld_fnc)+", \tDetail: "+str(_modbus_function[intToHex(funcion_modbus)])  +Colors.DEFAULT
			
			if '1' == verboseMode:

				print Colors.GREEN+"\t\t\t\t [+] Request  : "+ str(clr_req)  
				print Colors.GREEN+"\t\t\t\t [+] Response : "+ str(clr_resp)
				print Colors.GREEN+"\t\t\t\t [+] Exception code detail   : "+ str(info_error)

				# print Colors.GREEN+"\t\t\t\t [+] dbg response: "+Colors.ORANGE+ str(get_resp[16:].decode("hex"))+Colors.DEFAULT  
 

				print "\n"

	else:
		print Colors.GREEN+" [+] Valid Function: "+Colors.ORANGE+str(vld_fnc)+", \tDetail: "+str(_modbus_function[intToHex(funcion_modbus)])  +Colors.DEFAULT
		
		if '1' == verboseMode:
			# exception
			print Colors.GREEN+"\t\t\t\t [+] Request  : " + str(clr_req) 
			print Colors.GREEN+"\t\t\t\t [+] Response : " + str(clr_resp) 
			print Colors.GREEN+"\t\t\t\t [+] Exception code detail   : "+ str(info_error)
			
			# print Colors.GREEN+"\t\t\t\t [+] dbg response: "+Colors.ORANGE+ "[ "+str(get_resp[16:].decode("hex"))+" ]"+Colors.DEFAULT  
 

			print "\n"

def get_response_function(mb_response,valid_function):

	mbResp = {}
	mbResp[0] = mb_response[0:4] 	# Transaction
	mbResp[1] = mb_response[4:8] 	# Proto ID
	mbResp[2] = mb_response[8:12] 	# Length
	mbResp[3] = mb_response[12:14] 	# SlaveID
	mbResp[4] = mb_response[14:16]  # Function Code 
	mbResp[5] = mb_response[16:18]  # Function Code 

	function 		= mbResp[4]
	mb_exception 	= mbResp[5]

	return function,mb_exception


def functions_checks(hst,prt):	
	for modbus_functions in xrange(0,default_max_function):
		try:
			client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
			client.settimeout(100)
			client.connect((hst,prt))
		except Exception, e:
			print "connection fail.\n:"
			print e
			exit(0)

		mb_request = 	mb_adu(SID,intToHex(modbus_functions).zfill(2))
		
		client.send(mb_request.decode('hex'))
		modbus_response = (client.recv(2048)).encode("hex")
		time.sleep(.5)
		client.close()
		rspFnc = get_response_function(modbus_response,modbus_functions)
		valid = is_valid_function(modbus_functions,rspFnc[0],rspFnc[1],mb_request,modbus_response,1)
	print "\n\n"
	return valid 





try:
	functions_checks(HST,portModbus)
except KeyboardInterrupt as e:
	print Colors.RED+"\r\n [!] Bye... "+Colors.DEFAULT
	print str(e)
	exit(0)