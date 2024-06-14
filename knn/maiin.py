from flask import Flask, render_template, request, jsonify, flash, redirect, url_for, make_response, send_file, g
from werkzeug.utils import secure_filename
import json, os, sys, subprocess, psutil, socket, shutil, requests, io, datetime
import pyexcel as pe
import pandas as pd
sys.path.append('../database')
from sql import *
from function import *
sys.path.append('../function')
from dashboardFunction import dashboardFunction
from serverFunction import serverFunction
import logging
from logging.handlers import RotatingFileHandler

projectData = getData()
DataSession = checkSession()
# project_name, project_port, project_gateway, project_node, project_protocol = getData()

app = Flask(__name__)
app.config['SECRET_KEY'] = 'project'


formatter = logging.Formatter(
    '%(asctime)s %(levelname)s: %(message)s [in %(pathname)s:%(lineno)d]')
handler = RotatingFileHandler('app1.log', maxBytes=10000000, backupCount=5)
handler.setLevel(logging.INFO)
handler.setFormatter(formatter)
app.logger.addHandler(handler)

app.logger.setLevel(logging.INFO)
app.logger.info('Aplikasi dimulai')

@app.before_request
def before_request():
    g.project_data = getData()
    g.session_data = checkSession()
    g.device_setting = getDeviceSetting()
    g.sensors = groups.select()

@app.context_processor
def inject_global_data():
    return {
        'projectData': g.project_data,
        'sessionData': g.session_data,
        'deviceSetting': g.device_setting,
        'sensors': g.sensors,

    }

# @app.before_request
# def before_request():
#     g.project_data = getData()
#     g.session_data = checkSession()
#     g.device_setting = getDeviceSetting()
#     app.logger.info("Project Data: %s", g.project_data)
#     app.logger.info("Session Data: %s", g.session_data)
#     app.logger.info("Device Setting: %s", g.device_setting)

# @app.context_processor
# def inject_global_data():
#     data = {
#         'projectData': g.project_data,
#         'sessionData': g.session_data,
#         'deviceSetting': g.device_setting,
#     }
#     app.logger.info("Injected Data: %s", data)
#     return data


@app.route('/get/time')
def get_time():
    datetime = times.now()
    day = int(datetime.strftime("%w"))
    month = int(datetime.strftime("%m"))
    hari = ['Minggu','Senin','Selasa','Rabu','Kamis','Jum\'at','Sabtu']
    bulan = ['Januari','Februari','Maret','April','Mei','Juni','Juli','Agustus','September','Oktober','November','Desember']
    datetime = datetime.strftime(hari[day] + ", %d " + bulan[month-1] + " %Y %H:%M:%S")
    return datetime

# @app.route('/api/<input>/summary', methods=['GET'])
# def api_node_summary(input):
   # def parseData(displayName, serviceName, serviceData, serviceNum):
   #      serviceDetail = getServiceState(serviceName)
   #      if serviceDetail['service'] == 'active':
   #         serviceNum +=1
   #         serviceInfo = {
   #            'displayName': displayName,
   #            'statusOfService': serviceDetail['service'],
   #            'serviceState': serviceDetail['state'],
   #            'lastUpdate': serviceDetail['last_update']
   #         }

   #      else:
   #         serviceInfo = [displayName, serviceDetail['service'], '-', '-']
   #         serviceInfo = {
   #            'displayName': displayName,
   #            'statusOfService': serviceDetail['service'],
   #            'serviceState': '-',
   #            'lastUpdate': '-'
   #         }
   #      serviceData.append(serviceInfo)
   #      return serviceData, serviceNum
   # if input == "node":
   #    resultData, nodeService = [], 0
   #    resultData, nodeService = parseData('Routine Monitoring', 'connex_routine', resultData, nodeService)
   #    resultData, nodeService = parseData('Alarm Monitoring', 'connex_alarm', resultData, nodeService)
   #    resultData, nodeService = parseData('Display', 'connex_display', resultData, nodeService)
   #    resultData, nodeService = parseData('Buffer', 'connex_buffer', resultData, nodeService)
   #    resultData, nodeService = parseData('Log', 'connex_log', resultData, nodeService)
   #    resultData, nodeService = parseData('Synchronize', 'connex_sync', resultData, nodeService)
   #    resultData, nodeService = parseData('Authentication', 'connex_auth', resultData, nodeService)
   #    resultData, nodeService = parseData('Notification', 'connex_notif', resultData, nodeService)
   # elif input == "sensor":
   #    getSensorGroup = groups.select()
   #    resultData, sensorService = [], 0
   #    if getSensorGroup :
   #       for item in range(len(getSensorGroup)):
   #          resultData, sensorService = parseData(getSensorGroup[item]['name'], 'sensor' + str(getSensorGroup[item]['id']), resultData, sensorService)
   # elif input == "actuator":
   #    actuatorList = actuator.select()
   #    resultData, actuatorService = [], 0
   #    if actuatorList :
   #       for item in range((len(actuatorList))):
   #          resultData, actuatorService = parseData(actuatorList[item]['name'], actuatorList[item]['actuator_id'], resultData, actuatorService)         
   # return resultData 

@app.route('/api/device/summary', methods=['GET'])
def api_device_summary():
   def parseData(displayName, serviceName, serviceData, serviceNum):
        serviceDetail = getServiceState(serviceName)
        if serviceDetail['state'] == 'active':
           serviceNum +=1
           serviceInfo = {
              'displayName': displayName,
              'statusOfService': serviceDetail['state'],
              'serviceState': serviceDetail['log'],
              'lastUpdate': str(serviceDetail['last_update'])
           }
        else:
           serviceInfo = [displayName, serviceDetail['state'], '-', '-']
           serviceInfo = {
              'displayName': displayName,
              'statusOfService': serviceDetail['state'],
              'serviceState': '-',
              'lastUpdate': '-'
           }
        serviceData.append(serviceInfo)
        return serviceData, serviceNum
   infoNode, nodeService = [], 0
   infoNode, nodeService = parseData('Routine Monitoring', 'connex_routine', infoNode, nodeService)
   infoNode, nodeService = parseData('Alarm Monitoring', 'connex_alarm', infoNode, nodeService)
   infoNode, nodeService = parseData('Display', 'connex_display', infoNode, nodeService)
   infoNode, nodeService = parseData('Buffer', 'connex_buffer', infoNode, nodeService)
   infoNode, nodeService = parseData('Log', 'connex_log', infoNode, nodeService)
   infoNode, nodeService = parseData('Synchronize', 'connex_sync', infoNode, nodeService)
   infoNode, nodeService = parseData('Authentication', 'connex_auth', infoNode, nodeService)
   infoNode, nodeService = parseData('Notification', 'connex_notif', infoNode, nodeService)
   getSensorGroup = groups.select()
   infoSensor, sensorService = [], 0
   sensorDatas = {}
   if getSensorGroup :
      for item in range(len(getSensorGroup)):
         infoSensor, sensorService = parseData(getSensorGroup[item]['name'], 'sensor' + str(getSensorGroup[item]['id']), infoSensor, sensorService)
         sensorDatas[getSensorGroup[item]['name']] = []
         sensorList = sensor.selectByGroupFull(getSensorGroup[item]['id'])
         if len(sensorList) > 0 :
            for num in range(len(sensorList)):
               groupName = groups.selectOne(sensorList[num]['group_id'])
               if len(groupName) == 1:
                  groupName = groupName[0]['name']
               else:
                  groupName = 'N/A'   
               baseOid = getBaseOID(sensorList[num]['group_id'])
               oid = baseOid + "." + str(sensorList[num]['oid'])
               value, timestamp = sensorList[num]['value'], sensorList[num]['timestamp']
               serviceData = getServiceState("sensor" + str(sensorList[num]['group_id']))
               if value == None:
                  value, timestamp = '-', '-'   
               if serviceData['state'] == 'active':     
                  sensorDetail = {"oid": oid, "groupName": groupName, "sensorName": sensorList[num]['name'], "value": value, 
                                 "condition": sensorList[num]['conditions'], "timestamp": str(timestamp)}
               else:
                  sensorDetail = {"oid": oid, "groupName": groupName, "sensorName": sensorList[num]['name'], "value": "-", 
                                 "condition": "-", "timestamp": "-"}
               sensorDatas[getSensorGroup[item]['name']].append(sensorDetail)

   sensorList = sensor.select()
   sensorData = []
   if len(sensorList) > 0 :
      for num in range(len(sensorList)):
         groupName = groups.selectOne(sensorList[num]['group_id'])
         if len(groupName) == 1:
            groupName = groupName[0]['name']
         else:
            groupName = 'N/A'   
         baseOid = getBaseOID(sensorList[num]['group_id'])
         oid = baseOid + "." + str(sensorList[num]['oid'])
         value, timestamp = sensorList[num]['value'], sensorList[num]['timestamp']
         serviceData = getServiceState("sensor" + str(sensorList[num]['group_id']))
         if value == None:
            value, timestamp = '-', '-'   
         if serviceData['state'] == 'active':     
            sensorDetail = {"oid": oid, "groupName": groupName, "sensorName": sensorList[num]['name'], "value": value, 
                            "condition": sensorList[num]['conditions'], "timestamp": str(timestamp)}
         else:
            sensorDetail = {"oid": oid, "groupName": groupName, "sensorName": sensorList[num]['name'], "value": "-", 
                            "condition": "-", "timestamp": "-"}
         sensorData.append(sensorDetail)
   actuatorList = actuator.select()
   infoActuator, actuatorService = [], 0
   if len(actuatorList) > 0 :
      for item in range((len(actuatorList))):
         infoActuator, actuatorService = parseData(actuatorList[item]['name'], actuatorList[item]['actuator_id'], infoActuator, actuatorService)         
   resultData = {}
   resultData['service'] = {"node": infoNode, "sensor": infoSensor, "actuator": infoActuator}
   resultData['summary'] = {"sensor": sensorData, "actuator": actuatorList}
   # resultData['summarys'] = {"sensor": sensorDatas}
   return resultData   


@app.route('/')
def index():
    rule = str(request.url_rule)
    sessionData = checkSession() # ID, username, level
    projectData = getData() # projectNode, projectName
    settingData = getSetting() # deviceID, username, password, nodeID
    deviceSetting = getDeviceSetting() # uid, name, version

    def parseData(displayName, serviceName, serviceData, serviceNum):
        serviceDetail = getServiceState(serviceName)
        if serviceDetail['state'] == 'active':
           serviceNum +=1
           serviceInfo = {
              'displayName': displayName,
              'statusOfService': serviceDetail['state'],
              'serviceState': serviceDetail['log'],
              'lastUpdate': str(serviceDetail['last_update'])
           }
        else:
           serviceInfo = [displayName, serviceDetail['state'], '-', '-']
           serviceInfo = {
              'displayName': displayName,
              'statusOfService': serviceDetail['state'],
              'serviceState': '-',
              'lastUpdate': '-'
           }
        serviceData.append(serviceInfo)
        return serviceData, serviceNum
    infoNode, nodeService = [], 0
    infoNode, nodeService = parseData('Routine Monitoring', 'connex_routine', infoNode, nodeService)
    infoNode, nodeService = parseData('Alarm Monitoring', 'connex_alarm', infoNode, nodeService)
    infoNode, nodeService = parseData('Display', 'connex_display', infoNode, nodeService)
    infoNode, nodeService = parseData('Buffer', 'connex_buffer', infoNode, nodeService)
    infoNode, nodeService = parseData('Log', 'connex_log', infoNode, nodeService)
    infoNode, nodeService = parseData('Synchronize', 'connex_sync', infoNode, nodeService)
    infoNode, nodeService = parseData('Authentication', 'connex_auth', infoNode, nodeService)
    infoNode, nodeService = parseData('Notification', 'connex_notif', infoNode, nodeService)
    
    totalSensorOk, totalSensorMax, totalSensorMin = 0, 0, 0
    totalSensorError, totalAlarmInactive, totalSensorInactive, totalTolerance = 0, 0, 0, 0
    getSensorGroup = groups.select()
    infoSensor, sensorService = [], 0
    sensorDatas = {}
    if getSensorGroup :
       for item in range(len(getSensorGroup)):
          infoSensor, sensorService = parseData(getSensorGroup[item]['name'], 'sensor' + str(getSensorGroup[item]['id']), infoSensor, sensorService)
          sensorDatas[getSensorGroup[item]['name']] = []
          sensorList = sensor.selectByGroupFull(getSensorGroup[item]['id'])
          if len(sensorList) > 0 :
             for num in range(len(sensorList)):
                groupName = groups.selectOne(sensorList[num]['group_id'])
                if len(groupName) == 1:
                   groupName = groupName[0]['name']
                else:
                   groupName = 'N/A'   
                baseOid = getBaseOID(sensorList[num]['group_id'])
                oid = baseOid + "." + str(sensorList[num]['oid'])
                value, timestamp = sensorList[num]['value'], sensorList[num]['timestamp']
                serviceData = getServiceState("sensor" + str(sensorList[num]['group_id']))
                if value == None:
                   value, timestamp = '-', '-'   
                if serviceData['state'] == 'active':     
                   sensorDetail = {"oid": oid, "groupName": groupName, "sensorName": sensorList[num]['name'], "value": value, 
                                  "condition": sensorList[num]['conditions'], "timestamp": str(timestamp)}
                else:
                   sensorDetail = {"oid": oid, "groupName": groupName, "sensorName": sensorList[num]['name'], "value": "-", 
                                  "condition": "-", "timestamp": "-"}
                sensorDatas[getSensorGroup[item]['name']].append(sensorDetail)
    sensorList = sensor.select()
    sensorData = []
    if len(sensorList) > 0 :
       for num in range(len(sensorList)):
          groupName = groups.selectOne(sensorList[num]['group_id'])
          if len(groupName) == 1:
             groupName = groupName[0]['name']
          else:
             groupName = 'N/A'   
          baseOid = getBaseOID(sensorList[num]['group_id'])
          oid = baseOid + "." + str(sensorList[num]['oid'])
          value, timestamp = sensorList[num]['value'], sensorList[num]['timestamp']
          serviceData = getServiceState("sensor" + str(sensorList[num]['group_id']))
          if value == None:
             value, timestamp = '-', '-'   
          if serviceData['state'] == 'active':     
             sensorDetail = {"oid": oid, "groupName": groupName, "sensorName": sensorList[num]['name'], "value": value, 
                             "condition": sensorList[num]['conditions'], "timestamp": str(timestamp)}
          else:
             sensorDetail = {"oid": oid, "groupName": groupName, "sensorName": sensorList[num]['name'], "value": "-", 
                             "condition": "-", "timestamp": "-"}
          if sensorList[num]['conditions'] == 'Min': totalSensorMin+=1
          elif sensorList[num]['conditions'] == 'Max': totalSensorMax+=1
          elif sensorList[num]['conditions'] == 'Normal': totalSensorOk+=1
          elif sensorList[num]['conditions'] == 'Error': totalSensorError+=1
          elif sensorList[num]['conditions'] == 'Alarm Inactive': totalAlarmInactive +=1
          elif sensorList[num]['conditions'] == 'Tolerance': totalTolerance+=1
          else: totalSensorInactive+=1
          sensorData.append(sensorDetail)
    sensorStatus = {"ok":totalSensorOk, "max":totalSensorMax, "min":totalSensorMin, "error":totalSensorError, "alarm":totalAlarmInactive, "inactive":totalSensorInactive, "tolerance": totalTolerance}
      
    actuatorList = actuator.select()
    infoActuator, actuatorService = [], 0
    if len(actuatorList) > 0 :
       for item in range((len(actuatorList))):
          infoActuator, actuatorService = parseData(actuatorList[item]['name'], actuatorList[item]['actuator_id'], infoActuator, actuatorService)         
    resultData = {}
    resultData['service'] = {"node": infoNode, "sensor": infoSensor, "actuator": infoActuator}
    resultData['summary'] = {"sensor": sensorData, "actuator": actuatorList}
    # resultData['summarys'] = {"sensor": sensorDatas}
    
    # Node
    if nodeService == 8: nodeService = 'OK'  
    else: nodeService = 'Warning'    
    # Actuator
    if actuatorService == len(actuatorList): actuatorService = 'OK'
    else: actuatorService = 'Warning'
    # Sensor
    if sensorService == len(getSensorGroup): sensorService = 'OK'
    else: sensorService = 'Warning'
    if nodeService == 'OK' and sensorService == 'OK' and actuatorService == 'OK':
       overall = 'OK'
    else:
       overall = 'Warning'
       
    return render_template('index.html', rule=rule, sessionData=sessionData, projectData=projectData, settingData=settingData, deviceSetting=deviceSetting,  
                           sensorStatus=sensorStatus, nodeService=nodeService, sensorService=sensorService, actuatorService=actuatorService, overall=overall,
                           resultData=resultData)

@app.route('/login')
def login():
   rule = str(request.url_rule)
   sessionData = checkSession()
   projectData = getData()
   settingData = getSetting()
   deviceSetting = getDeviceSetting()

   return render_template('login.html', rule=rule, sessionData=sessionData, projectData=projectData, settingData=settingData, deviceSetting=deviceSetting)

@app.route('/login', methods=['POST'])
def login_post():
    getUsername = request.form.get('username')
    getPassword = request.form.get('password')
    getFlag = request.form.get('flag')
    port = getPort()
    data = {
       "username":getUsername,"password":getPassword,"flag":getFlag
      }
    
    try:
       login = requests.post('http://localhost:' + port + '/api/project/login', data=data)
       check = login.text
    except Exception as e:
       check = 0
    if check == "2":
       return redirect(url_for('index'))
    elif check == "1":
       flash('Wrong Password. Please Check Your Login and Try Again')
       return redirect(url_for('login'))
    else:
       flash('Wrong Username. Please Check Your Login and Try Again')
       return redirect(url_for('login'))

@app.route('/logout')
def logout():
   sessionData = checkSession()
   port = getPort()
   data = {"id":sessionData['id']}
   try:
      logout = requests.post('http://localhost:' + port + '/api/project/logout', data=data)
   except:
      pass
   return redirect(url_for('index'))

@app.route('/setting')
def setting_form():
    id, username, state, level = checkSession2()
    tab = request.args['tab']
    rule = str(request.url_rule)
    groupID, groupID2, groupID3, groupID4 = 'All', 'All', 'All', 'All'
    project_name, project_port, project_gateway, project_node, project_protocol = getData2()
    node_id, name, ip, firm_user, firm_pass = getSetting2()
    stateToken, tokens, expireToken = checkTokenHTTP()
    monitoring, sync, log, notif = getConnexSetting2()
    group = groups.select()
    sensors = sensor.select()
    actuators = actuator.select()
    actuators_param = actuator_param.select()
    actuators_schedule = actuator_schedule.select()
    sensorAll = sensor.select()
    param = params.select()
    param2 = paramList.select()
    monitorInterval = getInterval("monitoring")
    logInterval = getInterval("Log")
    oid = []

    if 'group' in request.args:
       if request.args['tab'] == 'sensor-list':
          groupID = request.args['group']
          if groupID != 'All':
             sensors = sensor.selectByGroupFull(groupID)
       elif request.args['tab'] == 'sensor-param-group':
          groupID2 = request.args['group']
          if groupID2 != 'All':
             param = params.selectByGroupFull(groupID2)
       elif request.args['tab'] == 'sensor-param-list':
          groupID3 = request.args['group']
          if groupID3 != 'All':
             param2 = paramList.selectByGroupFull(groupID3)
       elif request.args['tab'] == 'actuator_param':
          groupID4 = request.args['group']
          if groupID4 != 'All':
             param3 = paramList.selectByGroupFull(groupID4)

    for i in range(len(sensors)):
        base = params.selectByGroupParameter(sensors[i][2], "parent_oid")
        base_oid = 'Undefined'
        for i in base:
            base_oid = i[4]

        oid.append(base_oid)

    formulas = calibrateFormula.select()
    interval = intervals.select()
    attribute = attributes.select()

    if int(state) == 0:
       flash('Please Login to Access the Page')
       return redirect(url_for('login'))

    return render_template('setting.html', project_port=project_port, project_name=project_name, project_gateway=project_gateway, project_node=project_node, level=level, node_id=node_id, name=name, ip=ip, firm_user=firm_user, firm_pass=firm_pass, attribute=attribute, sensors=sensors, actuators=actuators, actuators_param=actuators_param, actuators_schedule=actuators_schedule, interval=interval, group=group, param=param, param2=param2, project_protocol=project_protocol, rule=rule, state=state, username=username, oid=oid, tab=tab, formulas=formulas, monitoring=monitoring, sync=sync, groupID=groupID, groupID2=groupID2, groupID3=groupID3, sensorAll=sensorAll, log=log, notif=notif, tokens=tokens, expireToken=expireToken, monitorInterval=monitorInterval, logInterval=logInterval)

@app.route('/setting_post', methods=['POST'])
def setting_post():
    import random, string
    node_id = request.form.get('node_id')
    ip = request.form.get('ip')
    firm_user = request.form.get('firm_user')
    firm_pass = request.form.get('firm_pass')
    sync = request.form.get('sync')
    monitoring = request.form.get('monitoring')
    log = request.form.get('log')
    notif = request.form.get('notif')

    fetch = setting.select()
    if node_id == '':
       node_id = 0
    if len(fetch) == 0:
       inserts = setting.insert(node_id,ip, firm_user, firm_pass, sync, monitoring, log, notif)
    else:
       updates = setting.update(node_id,ip, firm_user, firm_pass, sync, monitoring, log, notif)
    return redirect(url_for('setting_form', tab='parameter'))

# Menu Setting -> Device   
@app.route('/setting/device', methods= ['GET', 'POST'])
def settingDevice():
   rule = str(request.url_rule)
   sessionData = checkSession()   
   projectData = getData()
   settingData = getSetting()
   deviceSetting = getDeviceSetting()
   result = {'state':'', 'message':''}
   if 'result' in request.args:
        result = json.loads(request.args['result'])
   if request.method == 'POST':
      deviceUID = request.form.get('deviceUID')
      deviceName = request.form.get('deviceName')
      deviceVersion = request.form.get('deviceVersion')      
      deviceSetting = getDeviceSetting()

      if len(deviceSetting) == 0 :
         result = deviceSettinginsert(deviceUID, deviceName, deviceVersion)
      else :
         result = deviceSettingupdate(deviceUID, deviceName, deviceVersion)
      return redirect(url_for('settingDevice', result=result))

   # untuk sementara saya matikan dahulu check ini
   # if int(sessionData['state']) == 0:
   #    flash('Please Login to Access the Page')  
   #    return redirect(url_for('login'))

   return render_template('setting/device/deviceSetting.html', rule=rule, sessionData=sessionData, projectData=projectData, settingData=settingData, deviceSetting=deviceSetting, result=result)

@app.route('/setting-post/device', methods= ['POST'])
def settingPostDevice():
   deviceUID = request.form.get('deviceUID')
   deviceName = request.form.get('deviceName')
   deviceVersion = request.form.get('deviceVersion')
   
   deviceSetting = getDeviceSetting()
   action = deviceSettingDB.insert if len(deviceSetting) == 0 else deviceSettingDB.update
   action(deviceUID, deviceName, deviceVersion)

   return redirect(url_for('settingDevice'))

@app.route('/setting/connex', methods=['GET', 'POST'])
def settingConnex():
   rule = str(request.url_rule)
   sessionData = checkSession()  
   projectData = getData()
   connexSetting = getConnexSetting()
   deviceSetting = getDeviceSetting()
   intervalRoutine = intervalRoutineMonitorDB.select()
   routineLog = intervalRoutineLogDB.select()

   result = {'state':'', 'message':''}
   tab = 'monitor'
   if 'tab' in request.args:
      tab = request.args['tab']
   if 'result' in request.args:
      result = json.loads(request.args['result'])
   if request.method == 'POST':
      tab = request.form.get('tab')
      if tab == 'monitor':
         action = request.form.get('action')
         if action == 'monitor-setting':
            routineMonitor = request.form.get('routineMonitor')
            bufferMonitor = request.form.get('bufferMonitor')
            bufferMonitorInterval = request.form.get('bufferMonitorInterval')
            bufferMonitorUnit = request.form.get('bufferMonitorUnit')
            alarmMonitor = request.form.get('alarmMonitor')
            alarmMonitorUnit = request.form.get('alarmMonitorUnit')
            alarmMonitorInterval = request.form.get('alarmMonitorInterval')
            result = dashboardFunction.settingConnex.monitoring.update(routineMonitor, bufferMonitor, bufferMonitorInterval, bufferMonitorUnit, alarmMonitor, 
                                                                       alarmMonitorUnit, alarmMonitorInterval)
            return redirect(url_for('settingConnex', tab=tab, result=result))
         elif action == 'monitor-interval-add':
            interval = request.form.get('interval')
            unit = request.form.get('unit')
            result = dashboardFunction.settingConnex.monitoring.addRoutineInterval(interval, unit)
            return redirect(url_for('settingConnex', tab=tab, result=result))
         elif action == 'monitor-routine-update':
            idVal = request.form.get('idVal')
            interval = request.form.get('interval')
            unit = request.form.get('unit')
            result = dashboardFunction.settingConnex.monitoring.updateRoutineInterval(interval, unit, idVal)
            return redirect(url_for('settingConnex', tab=tab, result=result))
         elif action == 'monitor-routine-delete':
            idVal = request.form.get('idVal')
            result = dashboardFunction.settingConnex.monitoring.deleteRoutineInterval(idVal)
            return redirect(url_for('settingConnex', tab=tab, result=result))
      elif tab == 'sync':
         synchronize = request.form.get('synchronize')
         synchronizeInterval = request.form.get('synchronizeInterval')
         synchronizeUnit = request.form.get('synchronizeUnit')
         syncNode = request.form.get('syncNode')
         syncSensor = request.form.get('syncSensor')
         syncActuator = request.form.get('syncActuator')
         result = dashboardFunction.settingConnex.synchronize.update(synchronize, synchronizeInterval, synchronizeUnit, syncNode, syncSensor, syncActuator)
         return redirect(url_for('settingConnex', tab=tab, result=result))
      elif tab == 'notif':
         notification = request.form.get('notification')
         notificationInterval = request.form.get('notificationInterval')
         notificationUnit = request.form.get('notificationUnit')
         notifNodeWeb = request.form.get('notifNodeWeb')
         notifNodeWA = request.form.get('notifNodeWA')
         notifNodeEmail = request.form.get('notifNodeEmail')
         notifNodeTelegram = request.form.get('notifNodeTelegram')
         notifSensorWeb = request.form.get('notifSensorWeb')
         notifSensorWA = request.form.get('notifSensorWA')
         notifSensorEmail = request.form.get('notifSensorEmail')
         notifSensorTelegram = request.form.get('notifSensorTelegram')
         notifActuatorWeb = request.form.get('notifActuatorWeb')
         notifActuatorWA = request.form.get('notifActuatorWA')
         notifActuatorEmail = request.form.get('notifActuatorEmail')
         notifActuatorTelegram = request.form.get('notifActuatorTelegram')
         result = dashboardFunction.settingConnex.notification.update(notification, notificationInterval, notificationUnit, notifNodeWeb, notifNodeWA, notifNodeEmail, notifNodeTelegram, notifSensorWeb, notifSensorWA, notifSensorEmail, notifSensorTelegram, notifActuatorWeb, notifActuatorWA, notifActuatorEmail, notifActuatorTelegram)
         return redirect(url_for('settingConnex', tab=tab, result=result))
      elif tab == 'log':
         action = request.form.get('action')
         if action == 'log-setting' :
            log = request.form.get('log')
            result = dashboardFunction.settingConnex.internalLog.update(log)
            return redirect(url_for('settingConnex', tab=tab, result=result))
         elif action == 'log-routine-add' :
            interval = request.form.get('interval')
            unit = request.form.get('unit')
            result = dashboardFunction.settingConnex.internalLog.addRoutineInterval(interval, unit)
            return redirect(url_for('settingConnex', tab=tab, result=result))
         elif action == 'log-routine-update' :
            idVal = request.form.get('id')
            interval = request.form.get('interval')
            unit = request.form.get('unit')
            result = dashboardFunction.settingConnex.internalLog.updateRoutineInterval(interval, unit, idVal)
            return redirect(url_for('settingConnex', tab=tab, result=result))
         elif action == 'log-routine-delete' :
            idVal = request.form.get('id')
            result = dashboardFunction.settingConnex.internalLog.deleteRoutineInterval(idVal)
            return redirect(url_for('settingConnex', tab=tab, result=result))
      elif tab == 'system-service':
         action = request.form.get('action')
         if action == 'start-all-system-service' :
            result = dashboardFunction.settingConnex.systemService.runAll('start', 'all')
            return redirect(url_for('settingConnex', tab=tab, result=result))
         elif action == 'restart-all-system-service' :
            result= dashboardFunction.settingConnex.systemService.runAll('restart', 'all')
            return redirect(url_for('settingConnex', tab='system-service', result=result))
         elif action == 'stop-all-system-service' :
            result = dashboardFunction.settingConnex.systemService.runAll('stop', 'all')
            return redirect(url_for('settingConnex', tab='system-service', result=result))
         elif action == 'start-all-node-service' :
            result = dashboardFunction.settingConnex.systemService.runAll('start', 'node')
            return redirect(url_for('settingConnex', tab='system-service', result=result))
         elif action == 'restart-all-node-service' :
            result = dashboardFunction.settingConnex.systemService.runAll('restart', 'node')
            return redirect(url_for('settingConnex', tab='system-service', result=result))
         elif action == 'stop-all-node-service' :
            result = dashboardFunction.settingConnex.systemService.runAll('stop', 'node')
            return redirect(url_for('settingConnex', tab='system-service', result=result))
         elif action == 'start-all-sensor-service' :
            result = dashboardFunction.settingConnex.systemService.runAll('start', 'sensor')
            return redirect(url_for('settingConnex', tab='system-service', result=result))
         elif action == 'restart-all-sensor-service' :
            result = dashboardFunction.settingConnex.systemService.runAll('restart', 'sensor')            
            return redirect(url_for('settingConnex', tab='system-service', result=result))
         elif action == 'stop-all-sensor-service' :
            result = dashboardFunction.settingConnex.systemService.runAll('stop', 'sensor')
            return redirect(url_for('settingConnex', tab='system-service', result=result))
         elif action == 'start-all-actuator-service' :
            result = dashboardFunction.settingConnex.systemService.runAll('start', 'actuator')
            return redirect(url_for('settingConnex', tab='system-service', result=result))
         elif action == 'restart-all-actuator-service' :
            result = dashboardFunction.settingConnex.systemService.runAll('restart', 'actuator')
            return redirect(url_for('settingConnex', tab='system-service', result=result))
         elif action == 'stop-all-actuator-service' :
            result = dashboardFunction.settingConnex.systemService.runAll('stop', 'actuator')
            return redirect(url_for('settingConnex', tab='system-service', result=result))
      elif tab == 'system-alarm':   
         action = request.form.get('action')
         if action == 'reset-alarm-sensor-only' :
            result = dashboardFunction.settingConnex.systemAlarm.resetOnly()
            return redirect(url_for('settingConnex', tab='system-alarm', result=result))
         elif action == 'reset-alarm-sensor-with-restart' :
            result = dashboardFunction.settingConnex.systemAlarm.resetWithRestart()            
            return redirect(url_for('settingConnex', tab='system-alarm', result=result))
   # untuk sementara saya matikan dahulu check ini
   # if int(sessionData['state']) == 0:
   #    flash('Please Login to Access the Page')  
   #    return redirect(url_for('login'))
   return render_template('setting/connex/connexSetting.html', rule=rule, sessionData=sessionData, projectData=projectData, connexSetting=connexSetting, 
                                                                deviceSetting=deviceSetting, intervalRoutine=intervalRoutine, routineLog=routineLog, tab=tab, 
                                                                result=result)  

@app.route('/setting/server', methods=['GET', 'POST'])
def settingServerPage():
   rule = str(request.url_rule)
   sessionData = checkSession()  
   projectData = getData()
   deviceSetting = getDeviceSetting()

   result = {'state':'', 'message':''}
   if 'result' in request.args:
      result = json.loads(request.args['result'])
   tab = 'httpConfig'
   if 'tab' in request.args:
      tab = request.args['tab']    
   if request.method == 'POST':
      tab = request.form.get('tab')
      action = request.form.get('action')
      if action == 'httpConfig' or action == 'mqttConfig':
         server = action.replace("Config","")   
         domainAddress = request.form.get('domainAddress')
         ipAddress = request.form.get('ipAddress')
         port = request.form.get('port')
         username = request.form.get('user')
         password = request.form.get('passw')
         result = dashboardFunction.settingServer.updateConfig(domainAddress, ipAddress, port, username, password, server)
         return redirect(url_for('settingServerPage', tab=tab, result=result))
      elif action == 'httpAuth-clear':
         result = dashboardFunction.settingServer.http.deleteAuth()
         return redirect(url_for('settingServerPage', tab=tab, result=result))
      elif action == 'httpAuth-new':
         result = dashboardFunction.settingServer.http.getAuth()
         return redirect(url_for('settingServerPage', tab=tab, result=result))
      elif action == 'httpApi-add':
         name = request.form.get('name')
         parameter = request.form.get('parameter')
         type = request.form.get('type')
         api = request.form.get('api')
         result = dashboardFunction.settingServer.http.insertAPI(name, parameter, type, api)
         return redirect(url_for('settingServerPage', tab=tab, result=result))
      elif action == 'httpApi-update':
         id = request.form.get('id')
         name = request.form.get('name')
         parameter = request.form.get('parameter')
         type = request.form.get('type')
         api = request.form.get('api')
         result = dashboardFunction.settingServer.http.updateAPI(name, parameter, type, api, id)
         return redirect(url_for('settingServerPage', tab=tab, result=result))   
      elif action == 'httpApi-delete':
         id = request.form.get('id')
         result = dashboardFunction.settingServer.http.deleteAPI(id)
         return redirect(url_for('settingServerPage', tab=tab, result=result))
      elif action == 'mqttTopic-add':
         name = request.form.get('name')
         parameter = request.form.get('parameter')
         topic = request.form.get('topic')
         result = dashboardFunction.settingServer.mqtt.insertTopic(name, parameter, topic)
         return redirect(url_for('settingServerPage', tab=tab, result=result)) 
      elif action == 'mqttTopic-update':
         id = request.form.get('id')
         name = request.form.get('name')
         parameter = request.form.get('parameter')
         topic = request.form.get('topic')
         result = dashboardFunction.settingServer.mqtt.updateTopic(name, parameter, topic, id)
         return redirect(url_for('settingServerPage', tab=tab, result=result))
      elif action == 'mqttTopic-delete':
         id = request.form.get('id')
         result = dashboardFunction.settingServer.mqtt.deleteTopic(id)
         return redirect(url_for('settingServerPage', tab=tab, result=result))               
   serverData = serverFunction.getServerData()    
   # if int(sessionData['state']) == 0:
   #    flash('Please Login to Access the Page')  
   #    return redirect(url_for('login'))  
   return render_template('setting/server/serverSetting.html', rule=rule, sessionData=sessionData, projectData=projectData, deviceSetting=deviceSetting, tab=tab, 
                                                               result=result, serverData=serverData)

@app.route('/setting/sensor', methods=['GET', 'POST'])
def settingSensorPage():
   groupID, groupID2, groupID3 = 'All', 'All', 'All'
   rule = str(request.url_rule)
   sessionData = checkSession()  
   projectData = getData()
   connexSetting = getConnexSetting()
   deviceSetting = getDeviceSetting()
   sensorGroup = groups.select()
   sensorDetail = sensor.select()
   parameterGroup = params.select()
   parameterList = paramList.select()
   formulas = calibrateFormula.select()
   monitorInterval = intervalRoutineMonitorDB.select()
   logInterval = intervalRoutineLogDB.select()
   
   oid = []
   for item in range(len(sensorDetail)):
      base = params.selectByGroupParameter(sensorDetail[item]['group_id'], "parent_oid")
      base_oid = 'Undefined'
      for items in base:
         base_oid = items['value']
      oid.append(base_oid)
      
   if 'groupID' in request.args:
      groupID = request.args['groupID']
      if groupID != 'All':
         sensorDetail = sensor.selectByGroupFull(groupID)
         oid.clear()
         for item in range(len(sensorDetail)):
             base = params.selectByGroupParameter(sensorDetail[item]['group_id'], "parent_oid")
             base_oid = 'Undefined'
             for items in base:
                base_oid = items['value']
             oid.append(base_oid)          
   elif 'groupID2' in request.args:
      groupID2 = request.args['groupID2']
      if groupID2 != 'All':
         parameterGroup = params.selectByGroupFull(groupID2)
   elif 'groupID3' in request.args:
      groupID3 = request.args['groupID3']
      if groupID3 != 'All':
         parameterList = paramList.selectByGroupFull(groupID3)

   result = {'state':'', 'message':''}
   if 'result' in request.args:
      result = json.loads(request.args['result'])
   tab = 'sensorGroup'
   if 'tab' in request.args:
      tab = request.args['tab']  

   if request.method == 'POST':
      tab = request.form.get('tab')
      if tab == 'sensorGroup' :
         action = request.form.get('action')
         if action == 'sensorGroupAdd':
            name = request.form.get('name')
            interval = request.form.get('interval')
            unit = request.form.get('unit')
            frekuensi = request.form.get('frekuensi')
            enterAlarm = request.form.get('enterAlarm')
            exitAlarm = request.form.get('exitAlarm')
            errorAlarm = request.form.get('errorAlarm')
            port = getPort()
            result = dashboardFunction.settingSensor.group.insert(name, interval, unit, frekuensi, enterAlarm, exitAlarm, errorAlarm, port)           
            return redirect(url_for('settingSensorPage', tab=tab, result=result))
         elif action == 'sensorGroupUpdate':
            name = request.form.get('name')
            interval = request.form.get('interval')
            unit = request.form.get('unit')
            frekuensi = request.form.get('frekuensi')
            enterAlarm = request.form.get('enterAlarm')
            exitAlarm = request.form.get('exitAlarm')
            errorAlarm = request.form.get('errorAlarm')
            id = request.form.get('id')
            service_id = request.form.get('service_id')
            result = dashboardFunction.settingSensor.group.update(name, interval, unit, frekuensi, service_id, id, enterAlarm, exitAlarm, errorAlarm)
            return redirect(url_for('settingSensorPage', tab=tab, result=result))  
         elif action == 'sensorGroupDelete':
            id = request.form.get('id')
            name = request.form.get('name')
            serviceId = request.form.get('serviceId')
            port = getPort()
            result = dashboardFunction.settingSensor.group.delete(id, name, serviceId, port)
            return redirect(url_for('settingSensorPage', tab=tab, result=result))
      elif tab == 'sensorList' :
         action = request.form.get('action')
         if action == 'sensorListAdd':
            group_id = request.form.get('group_id')
            sensor_id = request.form.get('sensor_id')
            oid = request.form.get('oid')
            name = request.form.get('name')
            calibrate = request.form.get('calibrate')
            formula = request.form.get('formula')
            oid_tipe = request.form.get('oid_tipe')
            monitor = request.form.get('monitor')
            log = request.form.get('log')
            name = request.form.get('name')
            result = dashboardFunction.settingSensor.list.insert(sensor_id, oid, group_id, name, calibrate, formula, oid_tipe, monitor, log)
            return redirect(url_for('settingSensorPage', tab=tab, result=result)) 
         elif action == 'sensorListUpdate' :
            groupID = request.form.get('groupID')
            id = request.form.get('id')
            group_id = request.form.get('group_id')
            sensor_id = request.form.get('sensor_id')
            oid = request.form.get('oid')
            name = request.form.get('name')
            calibrate = request.form.get('calibrate')
            formula = request.form.get('formula')
            oid_tipe = request.form.get('oid_tipe')
            monitor = request.form.get('monitor')
            log = request.form.get('log')
            name = request.form.get('name')
            alarm = request.form.get('alarm')
            alarm_type = request.form.get('alarm_type')
            min = request.form.get('min')
            max = request.form.get('max')

            if sensorDetail :
               for itemSensor in range(len(sensorDetail)):
                  base_oid = getBaseOID(group_id)
                  last_oid = oid
                  Oid = f'{base_oid}.{last_oid}'
                  script = "sudo rm /tmp/" + Oid
                  os.system(script)

            result = dashboardFunction.settingSensor.list.update(sensor_id, oid, group_id, name, calibrate, formula, oid_tipe, monitor, log, alarm, min, max, alarm_type, id)
            return redirect(url_for('settingSensorPage', tab=tab, result=result, groupID=groupID))
         elif action == 'sensorListDelete' :
            id = request.form.get('id')
            name = request.form.get('name')
            groupID = request.form.get('groupID')
            result = dashboardFunction.settingSensor.list.delete(id, name)
            return redirect(url_for('settingSensorPage', tab=tab, result=result, groupID=groupID)) 
         elif action == 'sensorListFilter' :
            groupID = request.form.get('groupID')
            return redirect(url_for('settingSensorPage', tab=tab, groupID=groupID))
      elif tab == 'sensorParamGroup' :
         action = request.form.get('action')
         if action == 'sensorParamGroupAdd' :
            group_id = request.form.get('group_id')
            name = request.form.get('name')
            parameter = request.form.get('parameter')
            value = request.form.get('value')
            result = dashboardFunction.settingSensor.parameterGroup.insert(group_id, name, parameter, value)
            return redirect(url_for('settingSensorPage', tab=tab, result=result, groupID2=groupID2))
         elif action == 'sensorParamGroupUpdate' :
            groupID2 = request.form.get('groupID2')
            id = request.form.get('id')
            group_id = request.form.get('group_id')
            name = request.form.get('name')
            parameter = request.form.get('parameter')
            value = request.form.get('value')
            result = dashboardFunction.settingSensor.parameterGroup.update(group_id, name, parameter, value, id)
            return redirect(url_for('settingSensorPage', tab=tab, result=result, groupID2=groupID2))
         elif action == 'sensorParamGroupDelete' :
            groupID2 = request.form.get('groupID2')
            id = request.form.get('id')
            name = request.form.get('name')
            result = dashboardFunction.settingSensor.parameterGroup.delete(id, name)
            return redirect(url_for('settingSensorPage', tab=tab, result=result, groupID2=groupID2))  
         elif action == 'sensorParamGroupFilter' :
            groupID2 = request.form.get('groupID2')
            return redirect(url_for('settingSensorPage', tab=tab, groupID2=groupID2))
      elif tab == 'sensorParamList' :
         action = request.form.get('action')
         if action == 'sensorParamListAdd' :
            groupID3 = request.form.get('groupID3')
            sensorID = request.form.get('sensor_id')
            name = request.form.get('name')
            parameter = request.form.get('parameter')
            value = request.form.get('value')
            result = dashboardFunction.settingSensor.parameterList.insert(sensorID, name, parameter, value)
            return redirect(url_for('settingSensorPage', tab=tab, result=result, groupID3=groupID3))
         elif action == 'sensorParamListFilter' :
            groupID3 = request.form.get('groupID3')
            return redirect(url_for('settingSensorPage', tab=tab, groupID3=groupID3))
         elif action == 'sensorParamListUpdate' :
            groupID3 = request.form.get('groupID3')
            id = request.form.get('id')
            sensorID = request.form.get('sensor_id')
            name = request.form.get('name')
            parameter = request.form.get('parameter')
            value = request.form.get('value')
            result = dashboardFunction.settingSensor.parameterList.update(sensorID, name, parameter, value, id)
            return redirect(url_for('settingSensorPage', tab=tab, result=result, groupID3=groupID3))
         elif action == 'sensorParamListDelete' :
            groupID3 = request.form.get('groupID3')
            id = request.form.get('id')
            result = dashboardFunction.settingSensor.parameterList.delete(id)
            return redirect(url_for('settingSensorPage', tab=tab, result=result, groupID3=groupID3))                  
   # if int(sessionData['state']) == 0:
   #    flash('Please Login to Access the Page')  
   #    return redirect(url_for('login'))  
   return render_template('setting/sensor/sensorSetting.html', rule=rule, sessionData=sessionData, projectData=projectData, deviceSetting=deviceSetting, 
                          connexSetting=connexSetting, tab=tab, result=result, sensorGroup=sensorGroup, sensorDetail=sensorDetail,  monitorInterval=monitorInterval,  
                          logInterval=logInterval, oid=oid, formulas=formulas, parameterGroup=parameterGroup, parameterList=parameterList, 
                          groupID=groupID, groupID2=groupID2, groupID3=groupID3)

@app.route('/setting/actuator', methods=['GET', 'POST'])
def settingActuatorPage():
   rule = str(request.url_rule)
   sessionData = checkSession()  
   projectData = getData()
   connexSetting = getConnexSetting()
   deviceSetting = getDeviceSetting()
   actuatorList = actuator.select()
   actuatorParam = actuator_param.selectFull()
   actuatorSchedule = actuator_schedule.select()
   actuatorNow, actuatorNow2 = 'All', 'All'
   if 'actuatorNow' in request.args:
      actuatorNow = request.args['actuatorNow']
      if actuatorNow != 'All':
         actuatorParam = actuator_param.selectByActuatorIdFull(actuatorNow)
   elif 'actuatorNow2' in request.args:
      actuatorNow2 = request.args['actuatorNow2']
      if actuatorNow2 != 'All':
         actuatorSchedule = actuator_schedule.selectByActuatorIdFull(actuatorNow2)      

   result = {'state':'', 'message':''}
   if 'result' in request.args:
      result = json.loads(request.args['result'])
   tab = 'listActuator'
   if 'tab' in request.args:
      tab = request.args['tab']  

   if request.method == 'POST':
      tab = request.form.get('tab')
      if tab == 'listActuator' :
         action = request.form.get('action')
         if action == 'listActuatorAdd':
            actuatorID = request.form.get('actuatorID')
            name = request.form.get('name')
            result = dashboardFunction.settingActuator.list.insert(actuatorID, name)
            return redirect(url_for('settingActuatorPage', tab=tab, result=result))
         elif action == 'listActuatorUpdate':
            id = request.form.get('id')
            actuatorID = request.form.get('actuatorID')
            name = request.form.get('name')
            result = dashboardFunction.settingActuator.list.update(actuatorID, name, id)
            return redirect(url_for('settingActuatorPage', tab=tab, result=result))
         elif action == 'listActuatorDelete':
            id = request.form.get('id')
            name = request.form.get('name')
            result = dashboardFunction.settingActuator.list.delete(id, name)
            return redirect(url_for('settingActuatorPage', tab=tab, result=result))
      elif tab == 'paramActuator':
         action = request.form.get('action')
         if action == 'paramActuatorAdd':
            actuatorNow = request.form.get('actuatorNow')
            actuatorID = request.form.get('actuator_id')
            name = request.form.get('name')
            parameter = request.form.get('parameter')
            value = request.form.get('value')
            result = dashboardFunction.settingActuator.parameter.insert(actuatorID, name, parameter, value)
            return redirect(url_for('settingActuatorPage', tab=tab, result=result, actuatorNow=actuatorNow))
         elif action == 'paramActuatorUpdate':
            actuatorNow = request.form.get('actuatorNow')
            id = request.form.get('id')
            actuatorID = request.form.get('actuator_id')
            name = request.form.get('name')
            parameter = request.form.get('parameter')
            value = request.form.get('value')
            result = dashboardFunction.settingActuator.parameter.update(actuatorID, name, parameter, value, id)
            return redirect(url_for('settingActuatorPage', tab=tab, result=result, actuatorNow=actuatorNow)) 
         elif action == 'paramActuatorDelete':
            actuatorNow = request.form.get('actuatorNow')
            id = request.form.get('id')
            name = request.form.get('name')
            result = dashboardFunction.settingActuator.parameter.delete(id, name)
            return redirect(url_for('settingActuatorPage', tab=tab, result=result, actuatorNow=actuatorNow))
         elif action == 'paramActuatorFilter':
            actuatorNow = request.form.get('actuatorNow')
            return redirect(url_for('settingActuatorPage', tab=tab, actuatorNow=actuatorNow))
      elif tab == 'scheduleActuator':
         action = request.form.get('action')   
         if action == 'scheduleActuatorFilter':
            actuatorNow2 = request.form.get('actuatorNow2')
            return redirect(url_for('settingActuatorPage', tab=tab, actuatorNow2=actuatorNow2))
   # if int(sessionData['state']) == 0:
   #    flash('Please Login to Access the Page')  
   #    return redirect(url_for('login'))  
   return render_template('setting/actuator/actuatorSetting.html',  rule=rule, sessionData=sessionData, projectData=projectData, deviceSetting=deviceSetting, 
                                                                    connexSetting=connexSetting, tab=tab, result=result, actuatorList=actuatorList, 
                                                                    actuatorParam=actuatorParam, actuatorSchedule=actuatorSchedule, actuatorNow=actuatorNow,
                                                                    actuatorNow2=actuatorNow2)

@app.route('/setting/actuator2', methods=['GET', 'POST'])
def settingActuatorPage2():
   rule = str(request.url_rule)
   sessionData = checkSession() 
   projectData = getData()
   connexSetting = getConnexSetting()
   deviceSetting = getDeviceSetting()
   actuatorList = getActuatorDetail()
   actuatorParam = getActuatorParam()
   actuatorSchedule = getActuatorSchedule()

   result = {'state':'', 'message':''}
   if 'result' in request.args:
      result = json.loads(request.args['result'])
      
   tab = 'listActuator'
   if 'tab' in request.args:
      tab = request.args['tab']
   
   if request.method == 'POST':
      tab = request.form.get('tab')
      if tab == 'listActuator' :
         action = request.form.get('action')
         if action == 'listActuatorAdd':
            actuatorID = request.form.get('actuatorID')
            name = request.form.get('name')
            result = actuatorSetting.insert(actuatorID, name)
            return redirect(url_for('settingActuatorPage', tab=tab, result=result))  
         elif action == 'listActuatorUpdate':
            id = request.form.get('id')
            actuatorID = request.form.get('actuatorID')
            name = request.form.get('name')
            result = actuatorSetting.update(actuatorID, name, id)
            return redirect(url_for('settingActuatorPage', tab=tab, result=result))
         elif action == 'listActuatorDelete':
            id = request.form.get('id')
            name = request.form.get('name')
            result = actuatorSetting.delete(id, name)
            return redirect(url_for('settingActuatorPage', tab=tab, result=result)) 
      elif tab == 'paramActuator':
         action = request.form.get('action')
         if action == 'paramActuatorAdd':
            actuator_id = request.form.get('actuator_id')
            name = request.form.get('name')
            parameter = request.form.get('parameter')
            value = request.form.get('value')
            result = actuatorParamSetting.insert(actuator_id, name, parameter, value)
            return redirect(url_for('settingActuatorPage', tab=tab, result=result))
         elif action == 'paramActuatorUpdate':
            id = request.form.get('id')
            actuator = request.form.get('actuator')
            name = request.form.get('name')
            parameter = request.form.get('parameter')
            value = request.form.get('value')
            result = actuatorParamSetting.update(actuator, name, parameter, value, id)
            return redirect(url_for('settingActuatorPage', tab=tab, result=result)) 
         elif action == 'paramActuatorDelete':
            id = request.form.get('id')
            name = request.form.get('name')
            result = actuatorParamSetting.delete(id, name)
            return redirect(url_for('settingActuatorPage', tab=tab, result=result))  
   
   return render_template('setting/actuator/actuatorSetting.html', rule=rule, sessionData=sessionData, projectData=projectData, deviceSetting=deviceSetting, connexSetting=connexSetting, tab=tab, result=result, actuatorList=actuatorList, actuatorParam=actuatorParam, actuatorSchedule=actuatorSchedule)

@app.route('/token/reset')
def token_reset():
    token.updateValueByName("N/A", "token")
    token.updateValueByName("N/A", "expire")
    token.updateValueByName(0, "state")
    return redirect(url_for('setting_form', tab='token'))

@app.route('/token/get')
def token_get():
    fetch = setting.select()
    for i in fetch:
        node_id = i[1]
        ip = i[3]
        port = i[4]
        key = i[5]
    cek = attributes.selectOne("auth")
    if len(cek) > 0:
       for i in cek:
           param = i[2]
           link = 'http://'+ip+':'+port+param
           print('URL : ',link)
           user = packData.userPack(node_id, key)
           auth = http.getToken(link, user)
           if auth != 'Failed Get Token':
              update =  setting.updateToken(auth)
    return redirect(url_for('setting_form'))

@app.route('/attribute_post', methods=['POST'])
def attribute_post():
    name = request.form.get('name')
    value = request.form.get('value')
    inserts = attributes.insert(name,value)
    return redirect(url_for('setting_form', tab='api'))

@app.route('/attribute_update/<id>', methods=['POST'])
def attribute_update(id):
    name = request.form.get('name')
    value = request.form.get('value')
    updates = attributes.update(name,value,id)
    return redirect(url_for('setting_form', tab='api'))

@app.route('/attribute_delete/<id>')
def attribute_delete(id):
    deletes = attributes.deleteOne(id)
    return redirect(url_for('setting_form', tab='api'))

@app.route('/interval/add', methods=['POST'])
def interval_post():
    name = request.form.get('name')
    interval = request.form.get('interval')
    unit = request.form.get('unit')
    inserts = intervals.insert(name,interval,unit)
    return redirect(url_for('setting_form', tab='interval'))

@app.route('/interval/update/<id>', methods=['POST'])
def interval_update(id):
    name = request.form.get('name')
    interval = request.form.get('interval')
    unit = request.form.get('unit')
    updates = intervals.update(name,interval,unit,id)
    return redirect(url_for('setting_form', tab='interval'))

@app.route('/interval/delete/<id>')
def interval_delete(id):
    deletes = intervals.deleteOne(id)
    return redirect(url_for('setting_form', tab='interval'))

@app.route('/gateway/add', methods=['POST'])
def gateway_post():
    value = request.form.get('value')
    gateways = gateway.select()
    if len(gateways) == 0:
       inserts = gateway.insert(value)
    else:
       updates = gateway.update(value)
    return redirect(url_for('setting_form'))

@app.route('/actuator/add', methods=['POST'])
def actuator_post():
    base = "/home/connex"
    path = base + "/project/actuator/"
    project_name, project_port, project_gateway, project_node, project_protocol = getData2()
    actuator_id = request.form.get('actuator_id')
    name = request.form.get('name')
    inserts = actuator.insert(actuator_id,name)
    get_actuator = actuator.selectByActId(actuator_id)
    print(get_actuator)
    for i in get_actuator:
        id_act = i[0]
    filename1 = "actuator" + str(id_act)
    def file_read(source):
        f = open(source, 'r')
        data = f.readlines()
        f.close()
        return data
    def file_write(source, data):
        f = open(source, 'w')
        f.writelines(data)
        f.close()
    data = file_read(base + '/platform/storage/service.master')
    command = "/usr/bin/python3.7 " + filename1 + ".py"
    data[5] = "ExecStart={}\n".format(command)
    data[6] = "WorkingDirectory={}\n".format(path)
    file_write('/lib/systemd/system/' + filename1 + '.service', data)
    port = getPort()
    url = "http://localhost:" + port
    data = {"name":filename1, "path":path, "command":command}
    send = requests.post(url + "/api/service", data=data)
    fetch = requests.get(url + "/api/service/" + filename1)
    fetch = fetch.text
    fetch = json.loads(fetch)
    service_id = fetch['id']
    updateService = actuator.updateService(service_id, id_act)
    file_actuator = base + '/project/actuator/actuator' + str(id_act) + '.py'
    shutil.copy(base + "/platform/storage/actuator/actuator.py", file_actuator)
    data1 = file_read(file_actuator)
    data1[0] = 'id_act = ' + str(id_act) + '\n'
    file_write(file_actuator, data1)
    return redirect(url_for('setting_form', tab='actuator-list'))

@app.route('/actuator/update/<id>', methods=['POST'])
def actuator_update(id):
    project_name, project_port, project_gateway, project_node, project_protocol = getData()
    actuator_id = request.form.get('actuator_id')
    name = request.form.get('name')
    updates = actuator.update(actuator_id,name,id)
    if int(project_protocol) == 3:
       createOID()
    return redirect(url_for('setting_form', tab='actuator-list'))

@app.route('/actuator/delete/<id>')
def actuator_delete(id):
    base = "/home/connex"
    project_name, project_port, project_gateway, project_node, project_protocol = getData()
    fetch = actuator.selectById(id)
    for i in fetch:
        service_id = i[5]
    port = getPort()
    url = "http://localhost:" + port
    fetch = requests.get(url + "/api/service/delete/" + str(service_id))
    deletes = actuator.deleteOne(id)
    os.system("sudo rm " + base + "/project/actuator" + str(id) + ".py")
    os.system("sudo systemctl stop actuator" + str(id))
    os.system("sudo rm /lib/systemd/system/actuator" + str(id) + ".service")
    os.system("sudo systemctl daemon-reload")
    if int(project_protocol) == 3:
       createOID()
    return redirect(url_for('setting_form', tab='actuator-list'))

@app.route('/param_actuator/add', methods=['POST'])
def actuator_param_post():
    actuator_id = request.form.get('actuator_id')
    name = request.form.get('name')
    param = request.form.get('param')
    value = request.form.get('value')
    inserts = actuator_param.insert(actuator_id,name,param,value)
    return redirect(url_for('setting_form', tab='actuator-param'))

@app.route('/param_actuator/delete/<id>', methods=['POST'])
def actuator_param_delete(id):
    actuator_id = request.form.get('actuator_id')
    delete = actuator_param.deleteOne(id)
    return redirect(url_for('setting_form', tab='actuator-param'))

@app.route('/param_actuator/update/<id>', methods=['POST'])
def actuator_param_update(id):
    actuator_id = request.form.get('actuator_id')
    name = request.form.get('name')
    param = request.form.get('param')
    value = request.form.get('value')

    if name == "swing":
       if str(param) == '1' or str(param) == 'on' or str(param) == 'On' or str(param) == 'ON':
          param = 'on'
       elif str(param) == '0' or str(param) == 'off' or str(param) == 'Off' or str(param) == 'OFF':
          param = 'off'
       else:
          param = 'off'

    if name == 'temperature':
       check = str(param).isnumeric()
       if check == False:
          param = '16'

    updates = actuator_param.update(actuator_id,name,param,value,id)
    return redirect(url_for('setting_form', tab='actuator-param'))

@app.route('/sensor/add', methods=['POST'])
def sensor_post():
    project_name, project_port, project_gateway, project_node, project_protocol = getData()
    sensor_id = request.form.get('sensor_id')
    name = request.form.get('name')
    group_id = request.form.get('group_id')
    oid = request.form.get('oid')
    calibrate = request.form.get('calibrate')
    formula = request.form.get('formula')
    oid_tipe = request.form.get('oid_tipe')
    log = request.form.get('log')
    monitor = request.form.get('monitor')
    inserts = sensor.insert(sensor_id,oid,group_id,name,calibrate,formula,oid_tipe,monitor,log)
    createOID()
    return redirect(url_for('setting_form', tab='sensor-list'))

@app.route('/sensor/update/<id>', methods=['POST'])
def sensor_update(id):
    project_name, project_port, project_gateway, project_node, project_protocol = getData()
    groupNow = request.form.get('groupNow')
    sensor_id = request.form.get('sensor_id')
    name = request.form.get('name')
    group_id = request.form.get('group_id')
    last_oid_data = request.form.get('oid')
    sensors  = sensor.select()
    calibrate = request.form.get('calibrate')
    formula = request.form.get('formula')
    oid_tipe = request.form.get('oid_tipe')
    log = request.form.get('log')
    monitor = request.form.get('monitor')
    alarm = request.form.get('alarm')
    if alarm == 'No':
      alarm = 0
    elif alarm == 'Yes':
      alarm = 1
    alarm_type = request.form.get('alarm_type')
    if alarm_type == 'No Type':
      alarm_type = 0
    elif alarm_type == 'Min':
      alarm_type = 1
    elif alarm_type == 'Max':
      alarm_type = 2
    elif alarm_type == 'Min & Max':
      alarm_type = 3
    min = request.form.get('min')
    max = request.form.get('max')
    if len(sensors) > 0:
       for i in range(len(sensors)):
           base_oid = getBaseOID(sensors[i][2])
           last_oid = sensors[i][3]
           oid = base_oid + "." + str(last_oid)
           script = "sudo rm /tmp/" + oid
           os.system(script)
    updates = sensor.update(sensor_id, last_oid_data, group_id, name, calibrate, formula, oid_tipe, monitor, log, alarm, min, max, alarm_type, id)
    createOID()
    return redirect(url_for('setting_form', tab='sensor-list', group=groupNow))

@app.route('/sensor/delete/<id>', methods=['POST'])
def sensor_delete(id):
    project_name, project_port, project_gateway, project_node, project_protocol = getData()
    deletes = sensor.deleteOne(id)
    groupNow = request.form.get('groupNow')
    createOID()
    return redirect(url_for('setting_form', tab='sensor-list', group=groupNow))

@app.route('/sensor/filter', methods=['POST'])
def sensor_filter():
    groupID = request.form.get('groupID')
    return redirect(url_for('setting_form', tab='sensor-list', group=groupID))

@app.route('/param/add', methods=['POST'])
def param_post():
    group_id = request.form.get('group_id')
    name = request.form.get('name')
    parameter = request.form.get('parameter')
    value = request.form.get('value')
    inserts = params.insert(group_id,name,parameter,value)
    return redirect(url_for('setting_form', tab='sensor-param-group'))

@app.route('/param/update/<id>', methods=['POST'])
def param_update(id):
    groupNow = request.form.get('groupNow')
    group_id = request.form.get('group_id')
    name = request.form.get('name')
    parameter = request.form.get('parameter')
    value = request.form.get('value')
    updates = params.update(group_id,name,parameter,value,id)
    return redirect(url_for('setting_form', tab='sensor-param-group', group=groupNow))

@app.route('/param/delete/<id>', methods=['POST'])
def param_delete(id):
    groupNow = request.form.get('groupNow')
    deletes = params.deleteOne(id)
    return redirect(url_for('setting_form', tab='sensor-param-group', group=groupNow))

@app.route('/param/filter', methods=['POST'])
def param_filter():
    groupID = request.form.get('groupID')
    return redirect(url_for('setting_form', tab='sensor-param-group', group=groupID))

@app.route('/param/sensor/add', methods=['POST'])
def paramList_post():
    sensor_id = request.form.get('sensor_id')
    name = request.form.get('name')
    parameter = request.form.get('parameter')
    value = request.form.get('value')
    inserts = paramList.insert(sensor_id,name,parameter,value)
    return redirect(url_for('setting_form', tab='sensor-param-list'))

@app.route('/param/sensor/update/<id>', methods=['POST'])
def paramList_update(id):
    groupNow = request.form.get('groupNow')
    sensor_id = request.form.get('sensor_id')
    name = request.form.get('name')
    parameter = request.form.get('parameter')
    value = request.form.get('value')
    updates = paramList.update(sensor_id,name,parameter,value,id)
    return redirect(url_for('setting_form', tab='sensor-param-list', group=groupNow))

@app.route('/param/sensor/delete/<id>', methods=['POST'])
def paramList_delete(id):
    groupNow = request.form.get('groupNow')
    deletes = paramList.deleteOne(id)
    return redirect(url_for('setting_form', tab='sensor-param-list', group=groupNow))

@app.route('/param/sensor/filter', methods=['POST'])
def paramList_filter():
    groupID = request.form.get('groupID')
    return redirect(url_for('setting_form', tab='sensor-param-list', group=groupID))

@app.route('/group/add', methods=['POST'])
def group_post():
    base = "/home/connex"

    name = request.form.get('name')
    interval = request.form.get('interval')
    unit = request.form.get('unit')
    frekuensi = request.form.get('frekuensi')

    inserts = groups.insert(name,interval,unit,frekuensi,0)
    select = groups.selectByName(name)
    for i in range(len(select)):
        group_id = select[i][0]
    filename1 = "sensor" + str(group_id) #create sensor1.py
    filename2 = "check_sensor" + str(group_id)
    def file_read(source):
        f = open(source, 'r')
        data = f.readlines()
        f.close()
        return data
    def file_write(source, data):
        f = open(source, 'w')
        f.writelines(data)
        f.close()
    data = file_read(base + '/platform/storage/service.master')
    command = "/usr/bin/python " + filename1 + ".py"
    path = base + "project/sensor/"
    data[5] = "ExecStart={}\n".format(command)
    data[6] = "WorkingDirectory={}\n".format(path)
    file_write('/lib/systemd/system/' + filename1 + '.service', data)
    port = getPort()
    url = "http://localhost:" + port
    data = {"name":filename1, "path":path, "command":command}
    send = requests.post(url + "/api/service", data=data)
    fetch = requests.get(url + "/api/service/" + filename1)
    fetch = fetch.text
    fetch = json.loads(fetch)
    service_id = fetch['id']
    updates = groups.update(name,interval,unit,frekuensi,service_id,group_id)
    filesensor1 = base + '/project/sensor/sensor' + str(group_id) + '.py'
    filesensor2 = base + '/project/sensor/check_sensor' + str(group_id) + '.py'
    shutil.copy(base + "/platform/storage/sensor/sensor.py", filesensor1)
    shutil.copy(base + "/platform/storage/sensor/check_sensor.py", filesensor2)
    data1 = file_read(filesensor1)
    data1[0] = 'group_id = ' + str(group_id) + '\n'
    file_write(filesensor1, data1)
    data2 = file_read(filesensor2)
    data2[0] = 'group_id = ' + str(group_id) + '\n'
    file_write(filesensor2, data2)
    return redirect(url_for('setting_form', tab='sensor-group'))

@app.route('/group/update/<id>', methods=['POST'])
def group_update(id):
    name = request.form.get('name')
    interval = request.form.get('interval')
    unit = request.form.get('unit')
    frekuensi = request.form.get('frekuensi')
    service_id = request.form.get('service_id')
    enterAlarm = request.form.get('enterAlarm')
    exitAlarm = request.form.get('exitAlarm')
    errorAlarm = request.form.get('errorAlarm')
    updates = groups.update(name,interval,unit,frekuensi,service_id,enterAlarm,exitAlarm,errorAlarm,id)
    return redirect(url_for('setting_form', tab='sensor-group'))

@app.route('/group/delete/<id>')
def group_delete(id):
    base = "/home/connex"
    fetch = groups.selectOne(id)
    for i in fetch:
        service_id = i[5]
    port = getPort()
    url = "http://localhost:" + port
    fetch = requests.get(url + "/api/service/delete/" + str(service_id))
    deletes = groups.deleteOne(id)
    os.system("sudo rm " + base + "/project/sensor/sensor" + id + ".py")
    os.system("sudo rm " + base + "/project/sensor/check_sensor" + id + ".py")
    os.system("sudo systemctl stop sensor" + id)
    os.system("sudo rm /lib/systemd/system/sensor" + id + ".service")
    os.system("sudo systemctl daemon-reload")
    return redirect(url_for('setting_form', tab='sensor-group'))

@app.route('/log/send_node', methods=['GET','POST'])
def log_send_node():
    id, username, state, level = checkSession()
    rule = str(request.url_rule)
    project_name, project_port, project_gateway, project_node, project_protocol = getData()
    get_time = times.now()
    date1 = get_time.strftime("%Y-%m-%d")
    time1 = '00:00'
    date2 = get_time.strftime("%Y-%m-%d")
    time2 = get_time.strftime("%H:%M")
    if request.method == 'POST':
       date1 = request.form.get('date1')
       time1 = request.form.get('time1')
       date2 = request.form.get('date2')
       time2 = request.form.get('time2')
    datetime1 = date1 + ' ' + time1
    datetime2 = date2 + ' ' + time2
    if datetime1 == ' ' and datetime2 == ' ':
       fetch = logSendNode.selectMonitorAll()
    else:
       fetch = logSendNode.selectMonitorByTime(datetime1,datetime2)
    if int(state) == 0:
       flash('Please Login to Access the Page')
       return redirect(url_for('login'))
    return render_template('log_sendNode.html', rule=rule, fetch=fetch, date1=date1, time1=time1, date2=date2, time2=time2, project_name=project_name, project_port=project_port, project_gateway=project_gateway, project_node=project_node, state=state, username=username, level=level)

@app.route('/log/send_node/delete', methods=['POST'])
def log_send_node_deletes():
    datetime1 = request.form.get('datetime1')
    datetime2 = request.form.get('datetime2')
    if datetime1 == ' ' and datetime2 == ' ':
       deletes = logSendNode.deleteMonitorAll()
    else:
       deletes = logSendNode.deleteMonitorByTime(datetime1,datetime2)
    return redirect(url_for('log_send_node'))

@app.route('/log/send_node/delete/<id>')
def log_send_node_delete(id):
    delete = logSendNode.deleteOne(id)
    return redirect(url_for('log_send_node'))

@app.route('/log/send_node/download', methods=['POST'])
def log_send_node_download():
    datetimes1 = request.form.get('datetimes1')
    datetimes2 = request.form.get('datetimes2')
    if datetimes1 == ' ' and datetimes2 == ' ':
       fetch = logSendNode.selectMonitorAll()
    else:
       fetch = logSendNode.selectMonitorByTime(datetimes1,datetimes2)
    datas = Log.downloadMonitor(fetch)
    node_id, name, ip, firm_user, firm_pass = getSetting()
    filename = "Monitoring Log (" + str(name) + ").csv"
    pe.save_as(array=datas, dest_file_name="/home/connex/project/dashboard/file.csv", dest_delimiter=';')
    return send_file('/home/connex/project/dashboard/file.csv', attachment_filename=filename, as_attachment=True)

@app.route('/log/send_node/upload', methods=['POST'])
def log_send_node_upload():
    uploaded_file = request.files['file']
    data = pd.read_csv(uploaded_file, sep=';')
    for row in range(len(data)):
        datas = data['data'][row]
        datas = datas.replace("'","\"")
        buffer = data['buffer'][row]
        attempt = int(data['attempt'][row])
        state = data['state'][row]
        state = int(state)
        if buffer == 'Yes':
           buffer = 0
        elif buffer == 'No':
           buffer = 1
        else:
           buffer = 2
        type = data['type'][row]
        if type == 'Normal':
           type = 1
        elif type == 'Routine':
           type = 9
        elif type == 'Daily':
           type = 10
        elif type == 'Alarm Error':
           type = 4
        elif type == 'Alarm Max':
           type = 3
        elif type == 'Alarm Min':
           type = 2
        timestamp = data['timestamp'][row]
        inserts = logSendNode.insert(datas,state,buffer,timestamp,type,attempt)
    return redirect(url_for('log_send_node'))

@app.route('/log/buffer_node', methods=['GET','POST'])
def log_buffer_node():
    id, username, state, level = checkSession()
    rule = str(request.url_rule)
    project_name, project_port, project_gateway, project_node, project_protocol = getData()
    get_time = times.now()
    date1 = get_time.strftime("%Y-%m-%d")
    time1 = '00:00'
    date2 = get_time.strftime("%Y-%m-%d")
    time2 = get_time.strftime("%H:%M")
    if request.method == 'POST':
       date1 = request.form.get('date1')
       time1 = request.form.get('time1')
       date2 = request.form.get('date2')
       time2 = request.form.get('time2')
    datetime1 = date1 + ' ' + time1
    datetime2 = date2 + ' ' + time2
    if datetime1 == ' ' and datetime2 == ' ':
       fetch = logSendNode.selectBufferAll()
    else:
       fetch = logSendNode.selectBufferByTime(datetime1,datetime2)
    if int(state) == 0:
       flash('Please Login to Access the Page')
       return redirect(url_for('login'))
    return render_template('log_bufferNode.html', rule=rule, fetch=fetch, date1=date1, time1=time1, date2=date2, time2=time2,project_name=project_name, project_port=project_port, project_gateway=project_gateway, project_node=project_node, state=state, username=username, level=level)

@app.route('/log/buffer_node/delete', methods=['POST'])
def log_buffer_node_deletes():
    datetime1 = request.form.get('datetime1')
    datetime2 = request.form.get('datetime2')
    if datetime1 == ' ' and datetime2 == ' ':
       deletes = logSendNode.deleteBufferAll()
    else:
       deletes = logSendNode.deleteBufferByTime(datetime1,datetime2)
    return redirect(url_for('log_buffer_node'))

@app.route('/log/buffer_node/delete/<id>')
def log_buffer_node_delete(id):
    delete = logSendNode.deleteOne(id)
    return redirect(url_for('log_buffer_node'))

@app.route('/log/buffer_node/download', methods=['POST'])
def log_buffer_node_download():
    datetimes1 = request.form.get('datetimes1')
    datetimes2 = request.form.get('datetimes2')
    if datetimes1 == ' ' and datetimes2 == ' ':
       fetch = logSendNode.selectBufferAll()
    else:
       fetch = logSendNode.selectBufferByTime(datetimes1,datetimes2)
    datas = []
    header = ['data','state','buffer','type','attempt','timestamp']
    datas.append(header)
    for row in range(len(fetch)):
        data = []
        data.append(json.loads(fetch[row][1]))
        data.append(fetch[row][2])
        if int(fetch[row][3]) == 0:
           buffer = "Yes"
        elif int(fetch[row][3]) == 1:
           buffer = "No"
        else:
           buffer = "Done"
        data.append(buffer)
        typeData = fetch[row][5]
        if typeData == 1:
           data.append("Normal")
        elif typeData == 9:
           data.append("Routine")
        elif typeData == 10:
           data.append("Daily")
        elif typeData == 11:
           data.append("Replace")
        elif typeData == 4:
           data.append("Alarm Error")
        elif typeData == 3:
           data.append("Alarm Max")
        elif typeData == 2:
           data.append("Alarm Min")
        data.append(fetch[row][6])
        data.append(fetch[row][4])
        datas.append(data)
    node_id, name, ip, firm_user, firm_pass = getSetting()
    filename = "Buffer Log (" + str(name) + ").csv"
    pe.save_as(array=datas, dest_file_name="/home/connex/project/dashboard/file.csv", dest_delimiter=';')
    return send_file('/home/connex/project/dashboard/file.csv', attachment_filename=filename, as_attachment=True)

@app.route('/log/buffer_node/upload', methods=['POST'])
def log_buffer_node_upload():
    uploaded_file = request.files['file']
    data = pd.read_csv(uploaded_file, sep=';')
    for row in range(len(data)):
        datas = data['data'][row]
        datas = datas.replace("'","\"")
        buffer = data['buffer'][row]
        attempt = data['attempt'][row]
        attempt = int(attempt)
        state = data['state'][row]
        state = int(state)
        if buffer == 'Yes':
           buffer = 0
        elif buffer == 'No':
           buffer = 1
        else:
           buffer = 2
        type = data['type'][row]
        if type == 'Normal':
           type = 1
        elif type == 'Routine':
           type = 9
        elif type == 'Daily':
           type = 10
        elif type == 'Replace':
           type = 11
        elif type == 'Alarm Error':
           type = 4
        elif type == 'Alarm Max':
           type = 3
        elif type == 'Alarm Min':
           type = 2
        timestamp = data['timestamp'][row]
        inserts = logSendNode.insert(datas,state,buffer,timestamp,type,attempt)
    return redirect(url_for('log_buffer_node'))

@app.route('/log/sensor', methods=['GET','POST'])
def log_sensor():
    id, username, state, level = checkSession()
    rule = str(request.url_rule)
    project_name, project_port, project_gateway, project_node, project_protocol = getData()
    datetime1 = times.now()
    datetime2 = datetime1 - datetime.timedelta(hours=2)
    date1 = datetime2.strftime("%Y-%m-%d")
    time1 = datetime2.strftime("%H:%M")
    date2 = datetime1.strftime("%Y-%m-%d")
    time2 = datetime1.strftime("%H:%M")
    sensor_id, sensor_name = '', ''
    if request.method == 'POST':
       date1 = request.form.get('date1')
       time1 = request.form.get('time1')
       date2 = request.form.get('date2')
       time2 = request.form.get('time2')
       sensor_id = request.form.get('sensor_id')
    datetime1 = date1 + ' ' + time1
    datetime2 = date2 + ' ' + time2
    if sensor_id == '' and datetime1 == ' ' and datetime2 == ' ':
       fetch = logSensor.selectAll()
    elif sensor_id != '' and datetime1 == ' ' and datetime2 == ' ':
       fetch = logSensor.selectBySensor(sensor_id)
    else:
       fetch = logSensor.selectByTime(sensor_id,datetime1,datetime2)
    fetch2 = sensor.select()
    getSensor = sensor.selectById(sensor_id)
    if len(getSensor) > 0:
       for x in range(len(getSensor)):
           sensor_name = getSensor[x][4]
    if int(state) == 0:
       flash('Please Login to Access the Page')
       return redirect(url_for('login'))
    return render_template('log_sensor.html', rule=rule, fetch=fetch, date1=date1, time1=time1, date2=date2, time2=time2, fetch2=fetch2, sensor_id=sensor_id, project_name=project_name, project_port=project_port, project_gateway=project_gateway, project_node=project_node, state=state, username=username, sensor_name=sensor_name, level=level)

@app.route('/log/sensor/update/<id>', methods=['POST'])
def log_sensor_update(id):
    sensor_id = request.form.get('sensor_id')
    data = request.form.get('data')
    timestamp = request.form.get('timestamp')
    updates = logSensor.updateAll(sensor_id,data,timestamp,id)
    return redirect(url_for('log_sensor'))

@app.route('/log/sensor/delete', methods=['POST'])
def log_sensor_deletes():
    datetime1 = request.form.get('datetime1')
    datetime2 = request.form.get('datetime2')
    sensor_id = request.form.get('sensor_id')
    if sensor_id == '' and datetime1 == ' ' and datetime2 == ' ':
       deletes = logSensor.deleteAll()
    elif sensor_id != '' and datetime1 == ' ' and datetime2 == ' ':
       deletes = logSensor.deleteByNode(sensor_id)
    else:
       deletes = logSensor.deleteByTime(sensor_id,datetime1,datetime2)
    return redirect(url_for('log_sensor'))

@app.route('/log/sensor/delete/<id>')
def log_sensor_delete(id):
    delete = logSensor.deleteOne(id)
    return redirect(url_for('log_sensor'))

@app.route('/log/sensor/download', methods=['POST'])
def log_sensor_download():
    node_id, name, ip, firm_user, firm_pass = getSetting()
    datetimes1 = request.form.get('datetimes1')
    datetimes2 = request.form.get('datetimes2')
    sensor_id = request.form.get('sensor_id')
    if sensor_id == '' and datetimes1 == ' ' and datetimes2 == ' ':
       fetch = logSensor.selectAll()
    elif sensor_id != '' and datetimes1 == ' ' and datetimes2 == ' ':
       fetch = logSensor.selectBySensor(sensor_id)
    else:
       fetch = logSensor.selectByTime(sensor_id,datetimes1,datetimes2)
    datas = Log.downloadSensor(fetch)
    node_id, name, ip, firm_user, firm_pass = getSetting()
    filename = "Sensor Log (" + str(name) + ").csv"
    pe.save_as(array=datas, dest_file_name="/home/connex/project/dashboard/file.csv", dest_delimiter=';')
    return send_file('/home/connex/project/dashboard/file.csv', attachment_filename=filename, as_attachment=True)

@app.route('/log/sensor/upload', methods=['POST'])
def log_sensor_upload():
    uploaded_file = request.files['file']
    data = pd.read_csv(uploaded_file, sep=';')
    for row in range(len(data)):
        sensor_id = data['sensor_id'][row]
        get = sensor.selectOne(sensor_id)
        for i in get:
            id = i[0]
        id = int(id)
        data_sensor = data['data'][row]
        data_sensor = str(data_sensor)
        type = data['type'][row]
        if type == 'Normal':
           type = 1
        elif type == 'Routine':
           type = 9
        elif type == 'Daily':
           type = 10
        elif type == 'Alarm Error':
           type = 4
        elif type == 'Alarm Max':
           type = 3
        elif type == 'Alarm Min':
           type = 2
        timestamp = data['timestamp'][row]
        inserts = logSensor.insert(id,data_sensor,type,timestamp)
    return redirect(url_for('log_sensor'))

@app.route('/log/actuator', methods=['GET','POST'])
def log_actuator():
    id, username, state, level = checkSession()
    rule = str(request.url_rule)
    project_name, project_port, project_gateway, project_node, project_protocol = getData()
    get_time = times.now()
    date1 = get_time.strftime("%Y-%m-01")
    time1 = '00:00'
    date2 = get_time.strftime("%Y-%m-%d")
    time2 = get_time.strftime("%H:%M")
    actuators = actuator.select()
    if request.method == 'POST':
       date1 = request.form.get('date1')
       time1 = request.form.get('time1')
       date2 = request.form.get('date2')
       time2 = request.form.get('time2')
    datetime1 = date1 + ' ' + time1
    datetime2 = date2 + ' ' + time2
    if datetime1 == ' ' and datetime2 == ' ':
       fetch = logActuator.selectAll()
    else:
       fetch = logActuator.selectByTime(datetime1,datetime2)
    if int(state) == 0:
       flash('Please Login to Access the Page')
       return redirect(url_for('login'))
    return render_template('log_actuator.html', rule=rule, fetch=fetch, date1=date1, time1=time1, date2=date2, time2=time2, project_name=project_name, project_port=project_port, project_gateway=project_gateway, project_node=project_node, state=state, username=username, actuators=actuators, level=level)

@app.route('/log/actuator/update/<id>', methods=['POST'])
def log_actuator_update(id):
    actuator_id = request.form.get('actuator_id')
    value = request.form.get('value')
    trigger = request.form.get('trigger')
    timestamp = request.form.get('timestamp')
    updates = logActuator.updateAll(actuator_id,value,trigger,timestamp,id)
    return redirect(url_for('log_actuator'))

@app.route('/log/actuator/delete', methods=['POST'])
def log_actuator_deletes():
    datetime1 = request.form.get('datetime1')
    datetime2 = request.form.get('datetime2')
    if datetime1 == ' ' and datetime2 == ' ':
       deletes = logActuator.deleteAll()
    else:
       deletes = logActuator.deleteByTime(datetime1,datetime2)
    return redirect(url_for('log_actuator'))

@app.route('/log/actuator/delete/<id>')
def log_actuator_delete(id):
    delete = logActuator.deleteOne(id)
    return redirect(url_for('log_actuator'))

@app.route('/log/actuator/download', methods=['POST'])
def log_actuator_download():
    datetimes1 = request.form.get('datetimes1')
    datetimes2 = request.form.get('datetimes2')
    if datetimes1 == ' ' and datetimes2 == ' ':
       fetch = logActuator.selectAll()
    else:
       fetch = logActuator.selectByTime(datetimes1,datetimes2)
    datas = []
    header = ['actuator_id','value','trigger','timestamp']
    datas.append(header)
    for row in range(len(fetch)):
        data = []
        get_actuator = actuator.selectById(fetch[row][1])
        for i in get_actuator:
            actuator_name = i[1]
        data.append(actuator_name)
        data.append(fetch[row][2])
        if int(fetch[row][3]) == 0:
           action = "Boot"
        elif int(fetch[row][3]) == 1:
           action = "Server Remote"
        elif int(fetch[row][3]) == 2:
           action = "Schedule"
        else:
           action = "Local Remote"
        data.append(action)
        data.append(fetch[row][4])
        datas.append(data)
    sheet = pe.Sheet(datas)
    sheets = io.StringIO()
    sheet.save_to_memory("csv", sheets)
    node_id, name, ip, firm_user, firm_pass = getSetting()
    filename = "Actuator Log (Node " + str(name) + ").csv"
    output = make_response(sheets.getvalue())
    output.headers["Content-Disposition"] = "attachment; filename="+filename
    output.headers["Content-type"] = "text/csv"
    return output

@app.route('/log/actuator/upload', methods=['POST'])
def log_actuator_upload():
    uploaded_file = request.files['file']
    data = pd.read_csv(uploaded_file)
    for row in range(len(data)):
        actuator_id = data['actuator_id'][row]
        get_actuator = actuator.selectByActId(actuator_id)
        for i in get_actuator:
            id_actuator = i[0]
        value = data['value'][row]
        trigger = data['trigger'][row]
        if trigger == 'Boot':
           trigger = 0
        elif trigger == 'Server Remote':
           trigger = 1
        elif trigger == 'Schedule':
           trigger = 2
        else:
           trigger = 3
        timestamp = data['timestamp'][row]
        inserts = logActuator.insert(id_actuator,str(value),trigger,timestamp)
    return redirect(url_for('log_actuator'))

@app.route('/log/notif', methods=['GET','POST'])
def log_notif():
    id, username, state, level = checkSession()
    rule = str(request.url_rule)
    project_name, project_port, project_gateway, project_node, project_protocol = getData()
    get_time = times.now()
    date1 = get_time.strftime("%Y-%m-%d")
    time1 = '00:00'
    date2 = get_time.strftime("%Y-%m-%d")
    time2 = get_time.strftime("%H:%M")
    if request.method == 'POST':
       date1 = request.form.get('date1')
       time1 = request.form.get('time1')
       date2 = request.form.get('date2')
       time2 = request.form.get('time2')
    datetime1 = date1 + ' ' + time1
    datetime2 = date2 + ' ' + time2
    if datetime1 == ' ' and datetime2 == ' ':
       fetch = logNotif.selectAll()
    else:
       fetch = logNotif.selectByTime(datetime1,datetime2)
    if int(state) == 0:
       flash('Please Login to Access the Page')
       return redirect(url_for('login'))
    return render_template('log_notif.html', rule=rule, fetch=fetch, date1=date1, time1=time1, date2=date2, time2=time2, project_name=project_name, project_port=project_port, project_gateway=project_gateway, project_node=project_node, state=state, username=username, level=level)

@app.route('/log/notif/update/<id>', methods=['POST'])
def log_notif_update(id):
    types = request.form.get('type')
    notif = request.form.get('notif')
    subject = request.form.get('subject')
    message = request.form.get('message')
    state = request.form.get('state')
    create_time = request.form.get('create_time')
    send_time = request.form.get('send_time')
    updates = logNotif.updateAll(types,notif,subject,message,state,create_time,send_time,id)
    return redirect(url_for('log_notif'))

@app.route('/log/notif/delete', methods=['POST'])
def log_notif_deletes():
    datetime1 = request.form.get('datetime1')
    datetime2 = request.form.get('datetime2')
    if datetime1 == ' ' and datetime2 == ' ':
       deletes = logNotif.deleteAll()
    else:
       deletes = logNotif.deleteByTime(datetime1,datetime2)
    return redirect(url_for('log_notif'))

@app.route('/log/notif/delete/<id>')
def log_notif_delete(id):
    delete = logNotif.deleteOne(id)
    return redirect(url_for('log_notif'))

@app.route('/log/notif/download', methods=['POST'])
def log_notif_download():
    datetimes1 = request.form.get('datetimes1')
    datetimes2 = request.form.get('datetimes2')
    if datetimes1 == ' ' and datetimes2 == ' ':
       fetch = logNotif.selectAll()
    else:
       fetch = logNotif.selectByTime(datetimes1,datetimes2)
    datas = Log.downloadNotif(fetch)
    node_id, name, ip, firm_user, firm_pass = getSetting()
    filename = "Notificaton Log (Node " + str(name) + ").csv"
    pe.save_as(array=datas, dest_file_name="/home/connex/project/dashboard/file.csv", dest_delimiter=';')
    return send_file('/home/connex/project/dashboard/file.csv', attachment_filename=filename, as_attachment=True)

@app.route('/log/notif/upload', methods=['POST'])
def log_notif_upload():
    uploaded_file = request.files['file']
    data = pd.read_csv(uploaded_file, sep=';')
    for row in range(len(data)):
        types = data['type'][row]
        sensorData = data['sensor'][row]
        conditionData = data['condition'][row]
        notif = data['notif'][row]
        subject = data['subject'][row]
        message = data['message'][row]
        state = data['state'][row]
        create_time = data['create_time'][row]
        send_time = data['send_time'][row]
        if send_time == "-":
           inserts = logNotif.insert(types, sensorData, conditionData, notif, subject, message, state, create_time)
        else:
           inserts = logNotif.insertAll(types, sensorData, conditionData, notif, subject, message, state, create_time, send_time)
    return redirect(url_for('log_notif'))

@app.route('/log/error', methods=['GET','POST'])
def log_error():
    id, username, state, level = checkSession()
    rule = str(request.url_rule)
    project_name, project_port, project_gateway, project_node, project_protocol = getData()
    get_time = times.now()
    date1 = get_time.strftime("%Y-%m-%d")
    time1 = '00:00'
    date2 = get_time.strftime("%Y-%m-%d")
    time2 = get_time.strftime("%H:%M")
    if request.method == 'POST':
       date1 = request.form.get('date1')
       time1 = request.form.get('time1')
       date2 = request.form.get('date2')
       time2 = request.form.get('time2')
    datetime1 = date1 + ' ' + time1
    datetime2 = date2 + ' ' + time2
    if datetime1 == ' ' and datetime2 == ' ':
       fetch = logError.selectAll()
    else:
       fetch = logError.selectByTime(datetime1,datetime2)
    if int(state) == 0:
       flash('Please Login to Access the Page')
       return redirect(url_for('login'))
    return render_template('log_error.html', rule=rule, fetch=fetch, date1=date1, time1=time1, date2=date2, time2=time2, project_name=project_name, project_port=project_port, project_gateway=project_gateway, project_node=project_node, state=state, username=username, level=level)

@app.route('/log/error/delete', methods=['POST'])
def log_error_deletes():
    datetime1 = request.form.get('datetime1')
    datetime2 = request.form.get('datetime2')
    if datetime1 == ' ' and datetime2 == ' ':
       deletes = logError.deleteAll()
    else:
       deletes = logError.deleteByTime(datetime1,datetime2)
    return redirect(url_for('log_error'))

@app.route('/log/error/delete/<id>')
def log_error_delete(id):
    delete = logError.deleteOne(id)
    return redirect(url_for('log_error'))

@app.route('/log/error/download', methods=['POST'])
def log_error_download():
    datetimes1 = request.form.get('datetimes1')
    datetimes2 = request.form.get('datetimes2')
    if datetimes1 == ' ' and datetimes2 == ' ':
       fetch = logError.selectAll()
    else:
       fetch = logError.selectByTime(datetimes1,datetimes2)
    datas = Log.downloadError(fetch)
    node_id, name, ip, firm_user, firm_pass = getSetting()
    filename = "Error Log (Node " + str(name) + ").csv"
    pe.save_as(array=datas, dest_file_name="/home/connex/project/dashboard/file.csv", dest_delimiter=';')
    return send_file('/home/connex/project/dashboard/file.csv', attachment_filename=filename, as_attachment=True)

@app.route('/log/error/upload', methods=['POST'])
def log_error_upload():
    uploaded_file = request.files['file']
    data = pd.read_csv(uploaded_file, sep=';')
    for row in range(len(data)):
        service = data['service'][row]
        error = data['error'][row]
        file = data['filename'][row]
        line = data['line'][row]
        timestamp = data['timestamp'][row]
        inserts = logError.insert(str(service), str(error), str(file), str(line), timestamp)
    return redirect(url_for('log_error'))

@app.route('/calibrate/formula', methods=['GET','POST'])
def calibrate_formula():
    id, username, state, level = checkSession()
    rule = str(request.url_rule)
    project_name, project_port, project_gateway, project_node, project_protocol = getData()
    tab, result = '0', '-'
    formula_id, sample_value = '', ''
    formulas = calibrateFormula.select()
    if request.method == 'POST':
       tab = request.form.get('tab')
       if tab == '0':
          test = '21'
       elif tab == '1':
          formula_id = request.form.get('formula_id')
          sample_value = request.form.get('sample_value')
          result = subprocess.Popen(["python3", "/home/connex/project/calibrate/check_calibrate.py", "-f", formula_id, "-v", sample_value], stdout=subprocess.PIPE)
          (out, err) = result.communicate()
          result = out.decode('utf-8')
          result = result.split('\n')
    if int(state) == 0:
       flash('Please Login to Access the Page')
       return redirect(url_for('login'))
    return render_template('calibrate_formula.html', project_name=project_name, project_port=project_port, project_gateway=project_gateway, project_node=project_node, rule=rule, state=state, username=username, formulas=formulas, tab=tab, result=result, formula_id=formula_id, sample_value=sample_value, level=level)

@app.route('/calibrate/formula/add', methods=['POST'])
def calibrate_formula_add():
    name = request.form.get('name')
    calibrateFormula.insert(name,0)
    return redirect(url_for('calibrate_formula'))

@app.route('/calibrate/formula/update/<id>', methods=['POST'])
def calibrate_formula_update(id):
    name = request.form.get('name')
    calibrateFormula.updateNameByFormula(name,id)
    return redirect(url_for('calibrate_formula'))

@app.route('/calibrate/formula/delete/<id>', methods=['GET'])
def calibrate_formula_delete(id):
    calibrateFormula.deleteOne(id)
    return redirect(url_for('calibrate_formula'))

@app.route('/calculate/formula/<id>', methods=['GET'])
def calculate_formula(id):
    result = subprocess.Popen(["python3", "/home/connex/project/calibrate/calculate_calibrate.py", "-f", id], stdout=subprocess.PIPE)
    (out, err) = result.communicate()
    result = out.decode('utf-8')
    result = result.split('\n')
    return redirect(url_for('calibrate_formula'))

@app.route('/calibrate/sample', methods=['GET','POST'])
def calibrate_sample():
    id, username, state, level = checkSession()
    rule = str(request.url_rule)
    project_name, project_port, project_gateway, project_node, project_protocol = getData()
    tab = '0'
    sensor_id, result, formula_id = '', '-', ''
    sensors = groups.select()
    samples = calibrateSample.select()
    formulas = calibrateFormula.select()
    if request.method == 'POST':
       tab = request.form.get('tab')
       if tab == '0':
          sensor_id = request.form.get('sensor')
          service = checkActiveService('sensor' + str(sensor_id))
          if service == 'active':
             result = ['Please stop service sensor' + str(sensor_id) + " first before check the sensor"]
          else:
             filename = "check_sensor" + sensor_id + ".py"
             result = subprocess.Popen(["python3", "/home/connex/project/sensor/"+filename, "-t", "0"], stdout=subprocess.PIPE)
             (out, err) = result.communicate()
             result = out.decode('utf-8')
             result = result.split('\n')
       elif tab == '1':
          form = request.form.get('form')
          formula_id = request.form.get('formula_id')
          if form == 'add':
             formula = request.form.get('formula')
             value_sample = request.form.get('value_sample')
             value_reference = request.form.get('value_reference')
             calibrateSample.insert(formula, value_sample, value_reference)
             calculate = calibrateSample.selectByFormula(formula)
             calibrateFormula.updateSampleByFormula(len(calculate),formula)
             subprocess.Popen(["python3", "/home/connex/project/calibrate/calculate_calibrate.py", "-f", formula], stdout=subprocess.PIPE)
          elif form == 'delete':
             sample_id = request.form.get('sample_id')
             formula = request.form.get('formula')
             calibrateSample.deleteOne(sample_id)
             calculate = calibrateSample.selectByFormula(formula)
             calibrateFormula.updateSampleByFormula(len(calculate),formula)
             subprocess.Popen(["python3", "/home/connex/project/calibrate/calculate_calibrate.py", "-f", formula], stdout=subprocess.PIPE)
          elif form == 'update':
             sample_id = request.form.get('sample_id')
             formula = request.form.get('formula_new')
             formula_last = request.form.get('formula_last')
             value_sample = request.form.get('value_sample')
             value_reference = request.form.get('value_reference')
             calibrateSample.update(formula,value_sample,value_reference,sample_id)
             calculate = calibrateSample.selectByFormula(formula)
             calibrateFormula.updateSampleByFormula(len(calculate),formula)
             calculate2 = calibrateSample.selectByFormula(formula_last)
             calibrateFormula.updateSampleByFormula(len(calculate2),formula_last)
             subprocess.Popen(["python3", "/home/connex/project/calibrate/calculate_calibrate.py", "-f", formula], stdout=subprocess.PIPE)
             subprocess.Popen(["python3", "/home/connex/project/calibrate/calculate_calibrate.py", "-f", formula_last], stdout=subprocess.PIPE)
          if formula_id == "":
             samples = calibrateSample.select()
          else:
             samples = calibrateSample.selectByFormula(formula_id)
    if int(state) == 0:
       flash('Please Login to Access the Page')
       return redirect(url_for('login'))
    return render_template('calibrate_sample.html', sensors=sensors, project_name=project_name, project_port=project_port, project_gateway=project_gateway, project_node=project_node, rule=rule, sensor_id=sensor_id, result=result, state=state, username=username, formulas=formulas, tab=tab, formula_id=formula_id, samples=samples, level=level)

@app.route('/check/sensor', methods=['GET','POST'])
def check_sensor():
    id, username, state, level = checkSession2()
    rule = str(request.url_rule)
    project_name, project_port, project_gateway, project_node, project_protocol = getData2()
    sensor_id = ''
    result = '-'
    sensors = groups.select()
    app.logger.info("Sensors in route: %s", sensors)
   #  sensors = '2'
    if request.method == 'POST':
       sensor_id = request.form.get('sensor')
       app.logger.info("Selected sensor: %s", sensor_id)
       service = checkActiveService('sensor' + str(sensor_id))
      #  service = 'inactive'
       if service == 'active':
          result = ['Please stop service sensor' + str(sensor_id) + " first before check the sensor"]
          app.logger.warning("Service for sensor %s is active, prompting to stop service", sensor_id)
        
       else:
          filename = "check_sensor" + sensor_id + ".py"
         #  filename = "check_sensor1.py"
          result = subprocess.Popen(["python3", "/home/connex/project/sensor/"+filename, "-t", "1"], stdout=subprocess.PIPE)
          (out, err) = result.communicate()
          result = out.decode('utf-8')
          result = result.split('\n')
          app.logger.info("Sensor check result: %s", result)
    if int(state) == 0:
       flash('Please Login to Access the Page')
       return redirect(url_for('login'))
    return render_template('check_sensor.html', sensors=sensors, project_name=project_name, project_port=project_port, project_gateway=project_gateway, project_node=project_node, rule=rule, sensor_id=sensor_id, result=result, state=state, username=username, level=level)



# @app.route('/check/sensor', methods=['GET','POST'])
# def check_sensor():
#     id, username, state, level = checkSession2()
#     rule = str(request.url_rule)
#     project_name, project_port, project_gateway, project_node, project_protocol = getData2()
#     sensor_id = ''
#     result = '-'
#     sensors = groups.select()
#     if request.method == 'POST':
#        sensor_id = request.form.get('sensor')
#        service = checkActiveService('sensor' + str(sensor_id))
#        if service == 'active':
#           result = ['Please stop service sensor' + str(sensor_id) + " first before check the sensor"]
#        else:
#           filename = "check_sensor" + sensor_id + ".py"
#           result = subprocess.Popen(["python3", "/home/connex/project/sensor/"+filename, "-t", "1"], stdout=subprocess.PIPE)
#           (out, err) = result.communicate()
#           result = out.decode('utf-8')
#           result = result.split('\n')
#     if int(state) == 0:
#        flash('Please Login to Access the Page')
#        return redirect(url_for('login'))
#     return render_template('check_sensor.html', sensors=sensors, project_name=projectData['name'], project_port=projectData['port'], project_gateway=projectData['gateway'], project_node=projectData['node'], rule=rule, sensor_id=sensor_id, result=result, state=DataSession['state'], username=DataSession['username'], level=DataSession['level'])


# @app.route('/check/sensor', methods=['GET', 'POST'])
# def check_sensor():
#     id, username, state, level = checkSession()
#     rule = str(request.url_rule)
#     project_data = getData()
#     project_name = project_data['name']
#     project_port = project_data['port']
#     project_gateway = project_data['gateway']
#     project_node = project_data['node']
#     project_protocol = project_data['protocol']
    
#     sensor_id = ''
#     result = '-'
#     sensors = groups.select()
    
#     if request.method == 'POST':
#         sensor_id = request.form.get('sensor')
#         service = checkActiveService('sensor' + str(sensor_id))
#         if service == 'active':
#             result = ['Please stop service sensor' + str(sensor_id) + " first before check the sensor"]
#         else:
#             filename = "check_sensor" + sensor_id + ".py"
#             result = subprocess.Popen(["python3", "/home/connex/project/sensor/" + filename, "-t", "1"], stdout=subprocess.PIPE)
#             (out, err) = result.communicate()
#             result = out.decode('utf-8')
#             result = result.split('\n')
    
#     if state == 0:
#         flash('Please Login to Access the Page')
#         return redirect(url_for('login'))
    
#     return render_template(
#         'check_sensor.html',
#         sensors=sensors,
#         project_name=project_name,
#         project_port=project_port,
#         project_gateway=project_gateway,
#         project_node=project_node,
#         rule=rule,
#         sensor_id=sensor_id,
#         result=result,
#         state=state,
#         username=username,
#         level=level
#     )




@app.route('/check/actuator', methods=['GET','POST'])
def check_actuator():
    id, username, state, level = checkSession()
    rule = str(request.url_rule)
    project_name, project_port, project_gateway, project_node, project_protocol = getData()
    actuator_id, action = '', ''
    result = '-'
    actuators = actuator.select()
    if request.method == 'POST':
       actuator_id = request.form.get('actuator')
       action = request.form.get('action')
       filename = "check_actuator" + actuator_id + ".py"
       result = subprocess.Popen(["python3", "/home/connex/project/actuator/" + filename, "-a", action], stdout=subprocess.PIPE)
       (out, err) = result.communicate()
       result = out.decode('utf-8')
       result = result.split('\n')
    if int(state) == 0:
       flash('Please Login to Access the Page')
       return redirect(url_for('login'))
    return render_template('check_actuator.html', actuators=actuators, project_name=project_name, project_port=project_port, project_gateway=project_gateway, project_node=project_node,rule=rule, actuator_id=actuator_id, result=result, state=state, username=username, action=action)

@app.route('/check/send', methods=['GET','POST'])
def check_send():
    id, username, state, level = checkSession()
    rule = str(request.url_rule)
    project_name, project_port, project_gateway, project_node, project_protocol = getData()
    tipe = ''
    result = '-'
    if request.method == 'POST':
       tipe = request.form.get('tipe')
       if int(project_protocol) == 1:
          protocol = "http"
       elif int(project_protocol) == 2:
          protocol = "mqtt"
       elif int(project_protocol) == 3:
          protocol = "snmp"
       if tipe == 'node':
          filename = "/home/connex/project/node/check_" + protocol + ".py"
       elif tipe == 'gateway':
          filename = "/home/connex/project/gateway/check_send.py"
       result = subprocess.Popen(["python3", filename], stdout=subprocess.PIPE)
       (out, err) = result.communicate()
       result = out.decode('utf-8')
       result = result.split('\n')
       if result[0] == '':
          result = '-'
    if int(state) == 0:
       flash('Please Login to Access the Page')
       return redirect(url_for('login'))
    return render_template('check_send.html', project_name=project_name, project_port=project_port, project_gateway=project_gateway, project_node=project_node, rule=rule, result=result, tipe=tipe, state=state, username=username, level=level)

@app.route('/check/oid', methods=['GET','POST'])
def check_oid():
    id, username, state, level = checkSession()
    rule = str(request.url_rule)
    project_name, project_port, project_gateway, project_node, project_protocol = getData()
    check = ''
    result = '-'
    list_sensor = sensor.select()
    if request.method == 'POST':
       check = request.form.get('sensor')
       if check == "":
          result = "Please Select the Sensor"
       else:
          sensor_data = sensor.selectById(check)
          for i in sensor_data:
              group_id = i[2]
          result = subprocess.Popen(["python3", "../node/check_oid.py", "-i", check, "-g", str(group_id)], stdout=subprocess.PIPE)
          (out, err) = result.communicate()
          result = out.decode('utf-8')
          result = result.split('\n')
    if int(state) == 0:
       flash('Please Login to Access the Page')
       return redirect(url_for('login'))
    return render_template('check_oid.html', project_name=project_name, project_port=project_port, project_gateway=project_gateway, project_node=project_node, rule=rule, result=result, check=check, state=state, username=username, list_sensor=list_sensor, level=level)

@app.route('/display', methods=['GET','POST'])
def display():
    id, username, state, level = checkSession()
    rule = str(request.url_rule)
    project_name, project_port, project_gateway, project_node, project_protocol = getData()
    result = '-'
    import time
    path = "/home/connex/project/display/"
    files = os.path.exists(path + "display.tft")
    if request.method == 'POST':
       upload_type = request.form.get('upload')
       if upload_type == 'external':
          uploaded_file = request.files['file']
          filename = secure_filename(uploaded_file.filename)
       enable = checkEnableService('connex_display')
       if enable == 'enabled':
          os.system('systemctl disable connex_display')
          result = ['Display service detected enable, system already disable the display service.', 'Please reboot device before upload the file']
       else:
          service = checkActiveService('connex_display')
          if service == 'active':
             result = ['Display service detected active, system already stop the display service.', 'Please reboot device before upload the file']
             os.system('service connex_display stop')
          else:
             if upload_type == 'external':
                uploaded_file.save(os.path.join(path + "display_new.tft"))
                script = 'nextion-fw-upload /dev/ttyS0 ' + path + 'display_new.tft -b 115200 -ub 115200'
             else:
                script = 'nextion-fw-upload /dev/ttyS0 ' + path + 'display.tft -b 115200 -ub 115200'
             code = os.system(script)
             if int(code) == 0:
                if upload_type == 'external':
                   os.system("rm " + path + "display.tft")
                   os.system("mv " + path + "display_new.tft " + path + "display.tft")
                result = ['Success Upload Display File']
             else:
                if upload_type == 'external':
                   os.system("rm " + path + "display_new.tft")
                result = ['Error Upload Display File']
    if files == True:
       last = time.ctime(os.path.getmtime(path + "display.tft"))
    else:
       last = "-"
    if int(state) == 0:
       flash('Please Login to Access the Page')
       return redirect(url_for('login'))
    return render_template('display.html', project_name=project_name, project_port=project_port, project_gateway=project_gateway, project_node=project_node, rule=rule, state=state, username=username, result=result, last=last, files=files, level=level)

@app.route('/system/service')
def service_form():
    id, username, state, level = checkSession()
    rule = str(request.url_rule)
    project_name, project_port, project_gateway, project_node, project_protocol = getData()
    services = system.select()
    if int(state) == 0:
       flash('Please Login to Access the Page')
       return redirect(url_for('login'))
    return render_template('system_service.html', project_name=project_name, project_port=project_port, project_gateway=project_gateway, project_node=project_node, rule=rule, state=state, username=username, services=services, level=level)

@app.route('/service/enable/<name>')
def service_enable(name):
    os.system("sudo systemctl enable " + name)
    return redirect(url_for('service_form'))

@app.route('/service/disable/<name>')
def service_disable(name):
    os.system("sudo systemctl disable " + name)
    return redirect(url_for('service_form'))

@app.route('/service/stop/<name>')
def service_stop(name):
    os.system("sudo systemctl stop " + name)
    return redirect(url_for('service_form'))

@app.route('/service/start/<name>')
def service_start(name):
    os.system("sudo systemctl start " + name)
    return redirect(url_for('service_form'))

@app.route('/service/start/all')
def service_start_all():
    def run(name):
       os.system("sudo systemctl start " + name)
    import threading
    allService = getSystemInfo()
    if allService:
       action_threads = []
       for num in range(len(allService)):
           serviceName = allService[num]['name']
           if serviceName != 'outback_api' and serviceName != 'dashboard':
              action_thread = threading.Thread(target = run, args = [serviceName])
              action_thread.start()
              action_threads.append(action_thread)
       for action in action_threads:
           action.join()
   #  return redirect(url_for('settingConnex', tab='system'))
    return redirect(url_for('settingConnex'))

@app.route('/service/restart/all')
def service_restart_all():
    def run(name):
       os.system("sudo systemctl restart " + name)
    import threading
    allService = getSystemInfo()
    if allService:
       action_threads = []
       for num in range(len(allService)):
           serviceName = allService[num]['name']
           if serviceName != 'outback_api' and serviceName != 'dashboard':
              action_thread = threading.Thread(target = run, args = [serviceName])
              action_thread.start()
              action_threads.append(action_thread)
       for action in action_threads:
           action.join()
    return redirect(url_for('settingConnex'))

@app.route('/service/stop/all')
def service_stop_all():
    def run(name):
       os.system("sudo systemctl stop " + name)
    import threading
    allService = getSystemInfo()
    if allService:
       action_threads = []
       for num in range(len(allService)):
           serviceName = allService[num]['name']
           if serviceName != 'outback_api' and serviceName != 'dashboard':
              action_thread = threading.Thread(target = run, args = [serviceName])
              action_thread.start()
              action_threads.append(action_thread)
       for action in action_threads:
           action.join()
    return redirect(url_for('settingConnex'))

@app.route('/service/start/node')
def service_start_node():
    def run(name):
       os.system("sudo systemctl start " + name)
    import threading
    allService = getSystemInfo()
    if allService:
       action_threads = []
       for num in range(len(allService)):
           serviceName = allService[num]['name']
           if serviceName != 'outback_api' and serviceName != 'dashboard':
              if 'sensor' not in serviceName:
                 action_thread = threading.Thread(target = run, args = [serviceName])
                 action_thread.start()
                 action_threads.append(action_thread)
       for action in action_threads:
           action.join()
    return redirect(url_for('settingConnex'))

@app.route('/service/restart/node')
def service_restart_node():
    def run(name):
       os.system("sudo systemctl restart " + name)
    import threading
    allService = getSystemInfo()
    if allService:
       action_threads = []
       for index in range(len(allService)):
           serviceName = allService[index]['name']
           if serviceName != 'outback_api' and serviceName != 'dashboard':
              if 'sensor' not in serviceName:
                 action_thread = threading.Thread(target = run, args = [serviceName])
                 action_thread.start()
                 action_threads.append(action_thread)
       for action in action_threads:
           action.join()
    return redirect(url_for('settingConnex'))

@app.route('/service/stop/node')
def service_top_node():
    def run(name):
       os.system("sudo systemctl stop " + name)
    import threading
    allService = getSystemInfo()
    if len(allService) > 0:
       action_threads = []
       for index in range(len(allService)):
           serviceName = allService[index]['name']
           if serviceName != 'outback_api' and serviceName != 'dashboard':
              if 'sensor' not in serviceName:
                 action_thread = threading.Thread(target = run, args = [serviceName])
                 action_thread.start()
                 action_threads.append(action_thread)
       for action in action_threads:
           action.join()
    return redirect(url_for('settingConnex'))

@app.route('/service/start/sensor')
def service_start_sensor():
    def run(name):
       os.system("sudo systemctl start " + name)
    import threading
    allService = getSystemInfo()
    if len(allService) > 0:
       action_threads = []
       for index in range(len(allService)):
           serviceName = allService[index]['name']
           if 'sensor' in serviceName:
              action_thread = threading.Thread(target = run, args = [serviceName])
              action_thread.start()
              action_threads.append(action_thread)
       for action in action_threads:
           action.join()
    return redirect(url_for('settingConnex'))

@app.route('/service/restart/sensor')
def service_restart_sensor():
    def run(name):
       os.system("sudo systemctl restart " + name)
    import threading
    allService = getSystemInfo()
    if len(allService) > 0:
       action_threads = []
       for index in range(len(allService)):
           serviceName = allService[index]['name']
           if 'sensor' in serviceName:
              action_thread = threading.Thread(target = run, args = [serviceName])
              action_thread.start()
              action_threads.append(action_thread)
       for action in action_threads:
           action.join()
    return redirect(url_for('settingConnex'))

@app.route('/service/stop/sensor')
def service_stop_sensor():
    def run(name):
       os.system("sudo systemctl stop " + name)
    import threading
    allService = getSystemInfo()
    if len(allService) > 0:
       action_threads = []
       for index in range(len(allService)):
           serviceName = allService[index]['name']
           if 'sensor' in serviceName:
              action_thread = threading.Thread(target = run, args = [serviceName])
              action_thread.start()
              action_threads.append(action_thread)
       for action in action_threads:
           action.join()
    return redirect(url_for('settingConnex'))

@app.route('/service/start/actuator')
def service_start_actuator():
    def run(name):
       os.system("sudo systemctl start " + name)
    import threading
    allService = getSystemInfo()
    if len(allService) > 0:
       action_threads = []
       for index in range(len(allService)):
           serviceName = allService[index]['name']
           if 'actuator' in serviceName:
              action_thread = threading.Thread(target = run, args = [serviceName])
              action_thread.start()
              action_threads.append(action_thread)
       for action in action_threads:
           action.join()
    return redirect(url_for('settingConnex'))

@app.route('/service/restart/actuator')
def service_restart_actuator():
    def run(name):
       os.system("sudo systemctl restart " + name)
    import threading
    allService = getSystemInfo()
    if len(allService) > 0:
       action_threads = []
       for index in range(len(allService)):
           serviceName = allService[index]['name']
           if 'actuator' in serviceName:
              action_thread = threading.Thread(target = run, args = [serviceName])
              action_thread.start()
              action_threads.append(action_thread)
       for action in action_threads:
           action.join()
    return redirect(url_for('settingConnex'))

@app.route('/service/stop/actuator')
def service_stop_actuator():
    def run(name):
       os.system("sudo systemctl stop " + name)
    import threading
    allService = getSystemInfo()
    if len(allService) > 0:
       action_threads = []
       for index in range(len(allService)):
           serviceName = allService[index]['name']
           if 'actuator' in serviceName:
              action_thread = threading.Thread(target = run, args = [serviceName])
              action_thread.start()
              action_threads.append(action_thread)
       for action in action_threads:
           action.join()
    return redirect(url_for('settingConnex'))

@app.route('/sensor/reset/notif')
def sensor_reset_notif():
    dataSensor = getDataSensor.all()
    if dataSensor['numSensor'] > 0:
       for index in range(dataSensor['numSensor']):
           sensor.updateResetAlarm(dataSensor[index+1]['id'])
    logTolerance.deleteAll()
    logAlarm.deleteAll()
    return redirect(url_for('settingConnex'))

@app.route('/sensor/reset/notif/service')
def sensor_reset_notif_with_restart():
   #  if 'tab' in request.args:
   #    tab = request.args['tab']
   #    if tab == 'system':

    service_stop_sensor()
    dataSensor = getDataSensor.all()
    if dataSensor['numSensor'] > 0:
       for index in range(dataSensor['numSensor']):
           sensor.updateResetAlarm(dataSensor[index+1]['id'])
    logTolerance.deleteAll()
    logAlarm.deleteAll()
    service_start_sensor()
    return redirect(url_for('settingConnex'))

@app.route('/do/reboot')
def do_reboot():
    os.system("sudo reboot")
    return redirect('/')

if __name__ == '__main__':
   app.run(host='0.0.0.0', port=projectData['port'], debug=True)
