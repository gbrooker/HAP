// This file has been generated automatically from the macOS HomeKit
// framework definitions. Don't make changes to this file directly.
// Update this file using the `hap-update` tool.
//
// Generated on:              8 January 2021
// HomeKit framework version: 858
// macOS:                     Version 11.1 (Build 20C69)

import Foundation

public enum AccessoryType: String, Codable {
    case other = "1"
    case bridge = "2"
    case fan = "3"
    case garageDoorOpener = "4"
    case lightbulb = "5"
    case doorLock = "6"
    case outlet = "7"
    case `switch` = "8"
    case thermostat = "9"
    case sensor = "10"
    case securitySystem = "11"
    case door = "12"
    case window = "13"
    case windowCovering = "14"
    case programmableSwitch = "15"
    case rangeExtender = "16"
    case ipCamera = "17"
    case videoDoorbell = "18"
    case airPurifier = "19"
    case airHeater = "20"
    case airConditioner = "21"
    case airHumidifier = "22"
    case airDehumidifier = "23"
    case appleTV = "24"
    case speaker = "26"
    case airport = "27"
    case sprinkler = "28"
    case faucet = "29"
    case showerHead = "30"
    case television = "31"
    case targetController = "32"
    case wiFiRouter = "33"
    case audioReceiver = "34"
    case televisionSetTopBox = "35"
    case televisionStreamingStick = "36"
}

extension AccessoryType: CustomStringConvertible {
    public var description: String {
        switch self {
        case .other: return "Other"
        case .bridge: return "Bridge"
        case .fan: return "Fan"
        case .garageDoorOpener: return "Garage Door Opener"
        case .lightbulb: return "Lightbulb"
        case .doorLock: return "Door Lock"
        case .outlet: return "Outlet"
        case .`switch`: return "Switch"
        case .thermostat: return "Thermostat"
        case .sensor: return "Sensor"
        case .securitySystem: return "Security System"
        case .door: return "Door"
        case .window: return "Window"
        case .windowCovering: return "Window Covering"
        case .programmableSwitch: return "Programmable Switch"
        case .rangeExtender: return "Range Extender"
        case .ipCamera: return "IP Camera"
        case .videoDoorbell: return "Video Doorbell"
        case .airPurifier: return "Air Purifier"
        case .airHeater: return "Air Heater"
        case .airConditioner: return "Air Conditioner"
        case .airHumidifier: return "Air Humidifier"
        case .airDehumidifier: return "Air Dehumidifier"
        case .appleTV: return "Apple TV"
        case .speaker: return "Speaker"
        case .airport: return "AirPort"
        case .sprinkler: return "Sprinkler"
        case .faucet: return "Faucet"
        case .showerHead: return "Shower Head"
        case .television: return "Television"
        case .targetController: return "Target Controller"
        case .wiFiRouter: return "Wi-Fi Router"
        case .audioReceiver: return "Audio Receiver"
        case .televisionSetTopBox: return "Television Set Top Box"
        case .televisionStreamingStick: return "Television Streaming Stick"
        }
    }
}

public extension ServiceType {
    static let accessoryRuntimeInformation = ServiceType(0x0239)
    static let airPurifier = ServiceType(0x00BB)
    static let airQualitySensor = ServiceType(0x008D)
    static let battery = ServiceType(0x0096)
    static let carbonDioxideSensor = ServiceType(0x0097)
    static let carbonMonoxideSensor = ServiceType(0x007F)
    static let contactSensor = ServiceType(0x0080)
    static let diagnostics = ServiceType(0x0237)
    static let door = ServiceType(0x0081)
    static let doorbell = ServiceType(0x0121)
    static let fan = ServiceType(0x0040)
    static let fanV2 = ServiceType(0x00B7)
    static let faucet = ServiceType(0x00D7)
    static let filterMaintenance = ServiceType(0x00BA)
    static let garageDoorOpener = ServiceType(0x0041)
    static let heaterCooler = ServiceType(0x00BC)
    static let humidifierDehumidifier = ServiceType(0x00BD)
    static let humiditySensor = ServiceType(0x0082)
    static let info = ServiceType(0x003E)
    static let inputSource = ServiceType(0x00D9)
    static let irrigationSystem = ServiceType(0x00CF)
    static let label = ServiceType(0x00CC)
    static let leakSensor = ServiceType(0x0083)
    static let lightSensor = ServiceType(0x0084)
    static let lightbulb = ServiceType(0x0043)
    static let lockManagement = ServiceType(0x0044)
    static let lockMechanism = ServiceType(0x0045)
    static let microphone = ServiceType(0x0112)
    static let motionSensor = ServiceType(0x0085)
    static let occupancySensor = ServiceType(0x0086)
    static let outlet = ServiceType(0x0047)
    static let securitySystem = ServiceType(0x007E)
    static let slats = ServiceType(0x00B9)
    static let smokeSensor = ServiceType(0x0087)
    static let speaker = ServiceType(0x0113)
    static let statefulProgrammableSwitch = ServiceType(0x0088)
    static let statelessProgrammableSwitch = ServiceType(0x0089)
    static let `switch` = ServiceType(0x0049)
    static let television = ServiceType(0x00D8)
    static let temperatureSensor = ServiceType(0x008A)
    static let thermostat = ServiceType(0x004A)
    static let threadTransport = ServiceType(0x0701)
    static let transferTransportManagement = ServiceType(0x0203)
    static let valve = ServiceType(0x00D0)
    static let wiFiTransport = ServiceType(0x022A)
    static let window = ServiceType(0x008B)
    static let windowCovering = ServiceType(0x008C)
}

extension ServiceType: CustomStringConvertible {
    public var description: String {
        switch self {
        case .accessoryRuntimeInformation: return "Accessory Runtime Information"
        case .airPurifier: return "Air Purifier"
        case .airQualitySensor: return "Air Quality Sensor"
        case .battery: return "Battery"
        case .carbonDioxideSensor: return "Carbon dioxide Sensor"
        case .carbonMonoxideSensor: return "Carbon monoxide Sensor"
        case .contactSensor: return "Contact Sensor"
        case .diagnostics: return "Diagnostics"
        case .door: return "Door"
        case .doorbell: return "Doorbell"
        case .fan: return "Fan"
        case .fanV2: return "Fan"
        case .faucet: return "Faucet"
        case .filterMaintenance: return "Filter Maintenance"
        case .garageDoorOpener: return "Garage Door Opener"
        case .heaterCooler: return "Heater-Cooler"
        case .humidifierDehumidifier: return "Humidifier-Dehumidifier"
        case .humiditySensor: return "Humidity Sensor"
        case .info: return "Accessory Information Service"
        case .inputSource: return "Input Source"
        case .irrigationSystem: return "Irrigation-System"
        case .label: return "Label"
        case .leakSensor: return "Leak Sensor"
        case .lightSensor: return "Light Sensor"
        case .lightbulb: return "Lightbulb"
        case .lockManagement: return "Lock Management"
        case .lockMechanism: return "Lock Mechanism"
        case .microphone: return "Microphone"
        case .motionSensor: return "Motion Sensor"
        case .occupancySensor: return "Occupancy Sensor"
        case .outlet: return "Outlet"
        case .securitySystem: return "Security System"
        case .slats: return "Slats"
        case .smokeSensor: return "Smoke Sensor"
        case .speaker: return "Speaker"
        case .statefulProgrammableSwitch: return "Stateful Programmable Switch"
        case .statelessProgrammableSwitch: return "Stateless Programmable Switch"
        case .`switch`: return "Switch"
        case .television: return "Television"
        case .temperatureSensor: return "Temperature Sensor"
        case .thermostat: return "Thermostat"
        case .threadTransport: return "Thread Transport"
        case .transferTransportManagement: return "Transfer Transport Management"
        case .valve: return "Valve"
        case .wiFiTransport: return "Wi-Fi Transport"
        case .window: return "Window"
        case .windowCovering: return "Window Covering"
        case let .appleDefined(typeCode):
            let hex = String(typeCode, radix: 16).uppercased()
            return "Apple Defined (\(hex))"
        case let .custom(uuid):
            return "\(uuid)"
        }
    }
}

// swiftlint:disable no_grouping_extension
public extension CharacteristicType {
    static let accessoryFlags = CharacteristicType(0x00A6)
    static let active = CharacteristicType(0x00B0)
    static let activeIdentifier = CharacteristicType(0x00E7)
    static let administratorOnlyAccess = CharacteristicType(0x0001)
    static let applicationMatchingIdentifier = CharacteristicType(0x00A4)
    static let audioFeedback = CharacteristicType(0x0005)
    static let batteryLevel = CharacteristicType(0x0068)
    static let brightness = CharacteristicType(0x0008)
    static let ccaEnergyDetectThreshold = CharacteristicType(0x0246)
    static let ccaSignalDetectThreshold = CharacteristicType(0x0245)
    static let carbonDioxideDetected = CharacteristicType(0x0092)
    static let carbonDioxideLevel = CharacteristicType(0x0093)
    static let carbonDioxidePeakLevel = CharacteristicType(0x0094)
    static let carbonMonoxideDetected = CharacteristicType(0x0069)
    static let carbonMonoxideLevel = CharacteristicType(0x0090)
    static let carbonMonoxidePeakLevel = CharacteristicType(0x0091)
    static let characteristicValueActiveTransitionCount = CharacteristicType(0x024B)
    static let characteristicValueTransitionControl = CharacteristicType(0x0143)
    static let chargingState = CharacteristicType(0x008F)
    static let closedCaptions = CharacteristicType(0x00DD)
    static let colorTemperature = CharacteristicType(0x00CE)
    static let configuredName = CharacteristicType(0x00E3)
    static let contactSensorState = CharacteristicType(0x006A)
    static let coolingThresholdTemperature = CharacteristicType(0x000D)
    static let currentAirPurifierState = CharacteristicType(0x00A9)
    static let currentAirQuality = CharacteristicType(0x0095)
    static let currentDoorState = CharacteristicType(0x000E)
    static let currentFanState = CharacteristicType(0x00AF)
    static let currentHeaterCoolerState = CharacteristicType(0x00B1)
    static let currentHeatingCoolingState = CharacteristicType(0x000F)
    static let currentHorizontalTiltAngle = CharacteristicType(0x006C)
    static let currentHumidifierDehumidifierState = CharacteristicType(0x00B3)
    static let currentLightLevel = CharacteristicType(0x006B)
    static let currentMediaState = CharacteristicType(0x00E0)
    static let currentPosition = CharacteristicType(0x006D)
    static let currentRelativeHumidity = CharacteristicType(0x0010)
    static let currentSlatState = CharacteristicType(0x00AA)
    static let currentTemperature = CharacteristicType(0x0011)
    static let currentTiltAngle = CharacteristicType(0x00C1)
    static let currentTransport = CharacteristicType(0x022B)
    static let currentVerticalTiltAngle = CharacteristicType(0x006E)
    static let currentVisibilityState = CharacteristicType(0x0135)
    static let currentWaterLevel = CharacteristicType(0x00B5)
    static let displayOrder = CharacteristicType(0x0136)
    static let eventRetransmissionMaximum = CharacteristicType(0x023D)
    static let eventTransmissionCounters = CharacteristicType(0x023E)
    static let filterChangeIndication = CharacteristicType(0x00AC)
    static let filterLifeLevel = CharacteristicType(0x00AB)
    static let filterResetChangeIndication = CharacteristicType(0x00AD)
    static let firmwareRevision = CharacteristicType(0x0052)
    static let hardwareRevision = CharacteristicType(0x0053)
    static let heartBeat = CharacteristicType(0x024A)
    static let heatingThresholdTemperature = CharacteristicType(0x0012)
    static let holdPosition = CharacteristicType(0x006F)
    static let hue = CharacteristicType(0x0013)
    static let identifier = CharacteristicType(0x00E6)
    static let identify = CharacteristicType(0x0014)
    static let inUse = CharacteristicType(0x00D2)
    static let inputDeviceType = CharacteristicType(0x00DC)
    static let inputSourceType = CharacteristicType(0x00DB)
    static let isConfigured = CharacteristicType(0x00D6)
    static let labelIndex = CharacteristicType(0x00CB)
    static let labelNamespace = CharacteristicType(0x00CD)
    static let leakDetected = CharacteristicType(0x0070)
    static let lockControlPoint = CharacteristicType(0x0019)
    static let lockCurrentState = CharacteristicType(0x001D)
    static let lockLastKnownAction = CharacteristicType(0x001C)
    static let lockManagementAutoSecurityTimeout = CharacteristicType(0x001A)
    static let lockPhysicalControls = CharacteristicType(0x00A7)
    static let lockTargetState = CharacteristicType(0x001E)
    static let logs = CharacteristicType(0x001F)
    static let macRetransmissionMaximum = CharacteristicType(0x0247)
    static let macTransmissionCounters = CharacteristicType(0x0248)
    static let manufacturer = CharacteristicType(0x0020)
    static let maximumTransmitPower = CharacteristicType(0x0243)
    static let model = CharacteristicType(0x0021)
    static let motionDetected = CharacteristicType(0x0022)
    static let mute = CharacteristicType(0x011A)
    static let name = CharacteristicType(0x0023)
    static let nitrogenDioxideDensity = CharacteristicType(0x00C4)
    static let obstructionDetected = CharacteristicType(0x0024)
    static let occupancyDetected = CharacteristicType(0x0071)
    static let operatingStateResponse = CharacteristicType(0x0232)
    static let outletInUse = CharacteristicType(0x0026)
    static let ozoneDensity = CharacteristicType(0x00C3)
    static let pm10Density = CharacteristicType(0x00C7)
    static let pm2_5Density = CharacteristicType(0x00C6)
    static let pictureMode = CharacteristicType(0x00E2)
    static let ping = CharacteristicType(0x023C)
    static let positionState = CharacteristicType(0x0072)
    static let powerModeSelection = CharacteristicType(0x00DF)
    static let powerState = CharacteristicType(0x0025)
    static let productData = CharacteristicType(0x0220)
    static let programMode = CharacteristicType(0x00D1)
    static let programmableSwitchEvent = CharacteristicType(0x0073)
    static let programmableSwitchOutputState = CharacteristicType(0x0074)
    static let receivedSignalStrengthIndication = CharacteristicType(0x023F)
    static let receiverSensitivity = CharacteristicType(0x0244)
    static let relativeHumidityDehumidifierThreshold = CharacteristicType(0x00C9)
    static let relativeHumidityHumidifierThreshold = CharacteristicType(0x00CA)
    static let remainingDuration = CharacteristicType(0x00D4)
    static let remoteKey = CharacteristicType(0x00E1)
    static let rotationDirection = CharacteristicType(0x0028)
    static let rotationSpeed = CharacteristicType(0x0029)
    static let saturation = CharacteristicType(0x002F)
    static let securitySystemAlarmType = CharacteristicType(0x008E)
    static let securitySystemCurrentState = CharacteristicType(0x0066)
    static let securitySystemTargetState = CharacteristicType(0x0067)
    static let serialNumber = CharacteristicType(0x0030)
    static let setDuration = CharacteristicType(0x00D3)
    static let setupTransferTransport = CharacteristicType(0x0201)
    static let signalToNoiseRatio = CharacteristicType(0x0241)
    static let slatType = CharacteristicType(0x00C0)
    static let sleepDiscoveryMode = CharacteristicType(0x00E8)
    static let sleepInterval = CharacteristicType(0x023A)
    static let smokeDetected = CharacteristicType(0x0076)
    static let softwareRevision = CharacteristicType(0x0054)
    static let statusActive = CharacteristicType(0x0075)
    static let statusFault = CharacteristicType(0x0077)
    static let statusLowBattery = CharacteristicType(0x0079)
    static let statusTampered = CharacteristicType(0x007A)
    static let sulphurDioxideDensity = CharacteristicType(0x00C5)
    static let supportedCharacteristicValueTransitionConfiguration = CharacteristicType(0x0144)
    static let supportedDiagnosticsSnapshot = CharacteristicType(0x0238)
    static let supportedTransferTransportConfiguration = CharacteristicType(0x0202)
    static let swingMode = CharacteristicType(0x00B6)
    static let targetAirPurifierState = CharacteristicType(0x00A8)
    static let targetDoorState = CharacteristicType(0x0032)
    static let targetFanState = CharacteristicType(0x00BF)
    static let targetHeaterCoolerState = CharacteristicType(0x00B2)
    static let targetHeatingCoolingState = CharacteristicType(0x0033)
    static let targetHorizontalTiltAngle = CharacteristicType(0x007B)
    static let targetHumidifierDehumidifierState = CharacteristicType(0x00B4)
    static let targetMediaState = CharacteristicType(0x0137)
    static let targetPosition = CharacteristicType(0x007C)
    static let targetRelativeHumidity = CharacteristicType(0x0034)
    static let targetTemperature = CharacteristicType(0x0035)
    static let targetTiltAngle = CharacteristicType(0x00C2)
    static let targetVerticalTiltAngle = CharacteristicType(0x007D)
    static let targetVisibilityState = CharacteristicType(0x0134)
    static let temperatureDisplayUnits = CharacteristicType(0x0036)
    static let threadControlPoint = CharacteristicType(0x0704)
    static let threadNodeCapabilities = CharacteristicType(0x0702)
    static let threadOpenthreadVersion = CharacteristicType(0x0706)
    static let threadStatus = CharacteristicType(0x0703)
    static let transmitPower = CharacteristicType(0x0242)
    static let valveType = CharacteristicType(0x00D5)
    static let version = CharacteristicType(0x0037)
    static let volatileOrganicCompoundDensity = CharacteristicType(0x00C8)
    static let volume = CharacteristicType(0x0119)
    static let volumeControlType = CharacteristicType(0x00E9)
    static let volumeSelector = CharacteristicType(0x00EA)
    static let wiFiCapabilities = CharacteristicType(0x022C)
    static let wiFiConfigurationControl = CharacteristicType(0x022D)
}

extension CharacteristicType: CustomStringConvertible {
    public var description: String {
        switch self {
        case .accessoryFlags: return "Accessory Flags"
        case .active: return "Active"
        case .activeIdentifier: return "Active Identifier"
        case .administratorOnlyAccess: return "Administrator Only Access"
        case .applicationMatchingIdentifier: return "Application Matching Identifier"
        case .audioFeedback: return "Audio Feedback"
        case .batteryLevel: return "Battery Level"
        case .brightness: return "Brightness"
        case .ccaEnergyDetectThreshold: return "CCA Energy Detect Threshold"
        case .ccaSignalDetectThreshold: return "CCA Signal Detect Threshold"
        case .carbonDioxideDetected: return "Carbon dioxide Detected"
        case .carbonDioxideLevel: return "Carbon dioxide Level"
        case .carbonDioxidePeakLevel: return "Carbon dioxide Peak Level"
        case .carbonMonoxideDetected: return "Carbon monoxide Detected"
        case .carbonMonoxideLevel: return "Carbon monoxide Level"
        case .carbonMonoxidePeakLevel: return "Carbon monoxide Peak Level"
        case .characteristicValueActiveTransitionCount: return "Characteristic Value Active Transition Count"
        case .characteristicValueTransitionControl: return "Characteristic Value Transition Control"
        case .chargingState: return "Charging State"
        case .closedCaptions: return "Closed Captions"
        case .colorTemperature: return "Color Temperature"
        case .configuredName: return "Configured Name"
        case .contactSensorState: return "Contact Sensor State"
        case .coolingThresholdTemperature: return "Cooling Threshold Temperature"
        case .currentAirPurifierState: return "Current Air Purifier State"
        case .currentAirQuality: return "Current Air Quality"
        case .currentDoorState: return "Current Door State"
        case .currentFanState: return "Current Fan State"
        case .currentHeaterCoolerState: return "Current Heater-Cooler State"
        case .currentHeatingCoolingState: return "Current Heating Cooling State"
        case .currentHorizontalTiltAngle: return "Current Horizontal Tilt Angle"
        case .currentHumidifierDehumidifierState: return "Current Humidifier-Dehumidifier State"
        case .currentLightLevel: return "Current Light Level"
        case .currentMediaState: return "Current Media State"
        case .currentPosition: return "Current Position"
        case .currentRelativeHumidity: return "Current Relative Humidity"
        case .currentSlatState: return "Current Slat State"
        case .currentTemperature: return "Current Temperature"
        case .currentTiltAngle: return "Current Tilt Angle"
        case .currentTransport: return "Current Transport"
        case .currentVerticalTiltAngle: return "Current Vertical Tilt Angle"
        case .currentVisibilityState: return "Current Visibility State"
        case .currentWaterLevel: return "Current Water Level"
        case .displayOrder: return "Display Order"
        case .eventRetransmissionMaximum: return "Event Retransmission Maximum"
        case .eventTransmissionCounters: return "Event Transmission Counters"
        case .filterChangeIndication: return "Filter Change indication"
        case .filterLifeLevel: return "Filter Life Level"
        case .filterResetChangeIndication: return "Filter Reset Change Indication"
        case .firmwareRevision: return "Firmware Revision"
        case .hardwareRevision: return "Hardware Revision"
        case .heartBeat: return "Heart Beat"
        case .heatingThresholdTemperature: return "Heating Threshold Temperature"
        case .holdPosition: return "Hold Position"
        case .hue: return "Hue"
        case .identifier: return "Identifier"
        case .identify: return "Identify"
        case .inUse: return "In Use"
        case .inputDeviceType: return "Input Device Type"
        case .inputSourceType: return "Input Source Type"
        case .isConfigured: return "Is Configured"
        case .labelIndex: return "Label Index"
        case .labelNamespace: return "Label Namespace"
        case .leakDetected: return "Leak Detected"
        case .lockControlPoint: return "Lock Control Point"
        case .lockCurrentState: return "Lock Current State"
        case .lockLastKnownAction: return "Lock Last Known Action"
        case .lockManagementAutoSecurityTimeout: return "Lock Management Auto Security Timeout"
        case .lockPhysicalControls: return "Lock Physical Controls"
        case .lockTargetState: return "Lock Target State"
        case .logs: return "Logs"
        case .macRetransmissionMaximum: return "MAC Retransmission Maximum"
        case .macTransmissionCounters: return "MAC Transmission Counters"
        case .manufacturer: return "Manufacturer"
        case .maximumTransmitPower: return "Maximum Transmit Power"
        case .model: return "Model"
        case .motionDetected: return "Motion Detected"
        case .mute: return "Mute"
        case .name: return "Name"
        case .nitrogenDioxideDensity: return "Nitrogen dioxide Density"
        case .obstructionDetected: return "Obstruction Detected"
        case .occupancyDetected: return "Occupancy Detected"
        case .operatingStateResponse: return "Operating State Response"
        case .outletInUse: return "Outlet In Use"
        case .ozoneDensity: return "Ozone Density"
        case .pm10Density: return "PM10 Density"
        case .pm2_5Density: return "PM2.5 Density"
        case .pictureMode: return "Picture Mode"
        case .ping: return "Ping"
        case .positionState: return "Position State"
        case .powerModeSelection: return "Power Mode Selection"
        case .powerState: return "Power State"
        case .productData: return "Product Data"
        case .programMode: return "Program Mode"
        case .programmableSwitchEvent: return "Programmable Switch Event"
        case .programmableSwitchOutputState: return "Programmable Switch Output State"
        case .receivedSignalStrengthIndication: return "Received Signal Strength Indication"
        case .receiverSensitivity: return "Receiver Sensitivity"
        case .relativeHumidityDehumidifierThreshold: return "Relative Humidity Dehumidifier Threshold"
        case .relativeHumidityHumidifierThreshold: return "Relative Humidity Humidifier Threshold"
        case .remainingDuration: return "Remaining Duration"
        case .remoteKey: return "Remote Key"
        case .rotationDirection: return "Rotation Direction"
        case .rotationSpeed: return "Rotation Speed"
        case .saturation: return "Saturation"
        case .securitySystemAlarmType: return "Security System Alarm Type"
        case .securitySystemCurrentState: return "Security System Current State"
        case .securitySystemTargetState: return "Security System Target State"
        case .serialNumber: return "Serial Number"
        case .setDuration: return "Set Duration"
        case .setupTransferTransport: return "Setup Transfer Transport"
        case .signalToNoiseRatio: return "Signal-to-noise Ratio"
        case .slatType: return "Slat Type"
        case .sleepDiscoveryMode: return "Sleep Discovery Mode"
        case .sleepInterval: return "Sleep Interval"
        case .smokeDetected: return "Smoke Detected"
        case .softwareRevision: return "Software Revision"
        case .statusActive: return "Status Active"
        case .statusFault: return "Status Fault"
        case .statusLowBattery: return "Status Low Battery"
        case .statusTampered: return "Status Tampered"
        case .sulphurDioxideDensity: return "Sulphur dioxide Density"
        case .supportedCharacteristicValueTransitionConfiguration: return "Supported Characteristic Value Transition Configuration"
        case .supportedDiagnosticsSnapshot: return "Supported Diagnostics Snapshot"
        case .supportedTransferTransportConfiguration: return "Supported Transfer Transport Configuration"
        case .swingMode: return "Swing Mode"
        case .targetAirPurifierState: return "Target Air Purifier State"
        case .targetDoorState: return "Target Door State"
        case .targetFanState: return "Target Fan State"
        case .targetHeaterCoolerState: return "Target Heater-Cooler State"
        case .targetHeatingCoolingState: return "Target Heating Cooling State"
        case .targetHorizontalTiltAngle: return "Target Horizontal Tilt Angle"
        case .targetHumidifierDehumidifierState: return "Target Humidifier-Dehumidifier State"
        case .targetMediaState: return "Target Media State"
        case .targetPosition: return "Target Position"
        case .targetRelativeHumidity: return "Target Relative Humidity"
        case .targetTemperature: return "Target Temperature"
        case .targetTiltAngle: return "Target Tilt Angle"
        case .targetVerticalTiltAngle: return "Target Vertical Tilt Angle"
        case .targetVisibilityState: return "Target Visibility State"
        case .temperatureDisplayUnits: return "Temperature Display Units"
        case .threadControlPoint: return "Thread Control Point"
        case .threadNodeCapabilities: return "Thread Node Capabilities"
        case .threadOpenthreadVersion: return "Thread OpenThread Version"
        case .threadStatus: return "Thread Status"
        case .transmitPower: return "Transmit Power"
        case .valveType: return "Valve Type"
        case .version: return "Version"
        case .volatileOrganicCompoundDensity: return "Volatile Organic Compound Density"
        case .volume: return "Volume"
        case .volumeControlType: return "Volume Control Type"
        case .volumeSelector: return "Volume Selector"
        case .wiFiCapabilities: return "Wi-Fi Capabilities"
        case .wiFiConfigurationControl: return "Wi-Fi Configuration Control"
        case let .appleDefined(typeCode):
            let hex = String(typeCode, radix: 16).uppercased()
            return "Apple Defined (\(hex))"
        case let .custom(uuid):
            return "\(uuid)"
        }
    }
}

public enum CharacteristicFormat: String, Codable {
    case bool
    case data
    case float
    case int
    case string
    case tlv8
    case uint16
    case uint32
    case uint8
}

public enum CharacteristicUnit: String, Codable {
    case arcdegrees
    case celsius
    case fahrenheit
    case lux
    case microgramsPerMCubed
    case percentage
    case ppm
    case seconds
}

public class Enums {
    public enum Active: UInt8, CharacteristicValueType {
        case inactive = 0
        case active = 1
    }

    public enum CarbonDioxideDetected: UInt8, CharacteristicValueType {
        case normal = 0
        case abnormal = 1
    }

    public enum ChargingState: UInt8, CharacteristicValueType {
        case notCharging = 0
        case charging = 1
        case notChargeable = 2
    }

    public enum ClosedCaptions: UInt8, CharacteristicValueType {
        case disabled = 0
        case enabled = 1
    }

    public enum ContactSensorState: UInt8, CharacteristicValueType {
        case detected = 0
        case notdetected = 1
    }

    public enum CurrentAirPurifierState: UInt8, CharacteristicValueType {
        case inactive = 0
        case idle = 1
        case purifyingAir = 2
    }

    public enum CurrentAirQuality: UInt8, CharacteristicValueType {
        case unknown = 0
        case excellent = 1
        case good = 2
        case fair = 3
        case inferior = 4
        case poor = 5
    }

    public enum CurrentDoorState: UInt8, CharacteristicValueType {
        case open = 0
        case closed = 1
        case opening = 2
        case closing = 3
        case stopped = 4
    }

    public enum CurrentFanState: UInt8, CharacteristicValueType {
        case inactive = 0
        case idle = 1
        case blowing = 2
    }

    public enum CurrentHeaterCoolerState: UInt8, CharacteristicValueType {
        case inactive = 0
        case idle = 1
        case heating = 2
        case cooling = 3
    }

    public enum CurrentHeatingCoolingState: UInt8, CharacteristicValueType {
        case off = 0
        case heat = 1
        case cool = 2
    }

    public enum CurrentHumidifierDehumidifierState: UInt8, CharacteristicValueType {
        case inactive = 0
        case idle = 1
        case humidifying = 2
        case dehumidifying = 3
    }

    public enum CurrentSlatState: UInt8, CharacteristicValueType {
        case inactive = 0
        case fixed = 1
        case swinging = 2
        case jammed = 3
    }

    public enum CurrentVisibilityState: UInt8, CharacteristicValueType {
        case shown = 0
        case hidden = 1
        case state2 = 2
        case state3 = 3
    }

    public enum FilterChangeIndication: UInt8, CharacteristicValueType {
        case noChange = 0
        case change = 1
    }

    public enum InputDeviceType: UInt8, CharacteristicValueType {
        case other = 0
        case tv = 1
        case recording = 2
        case tuner = 3
        case playback = 4
        case audiosystem = 5
    }

    public enum InputSourceType: UInt8, CharacteristicValueType {
        case other = 0
        case homescreen = 1
        case tuner = 2
        case hdmi = 3
        case compositevideo = 4
        case svideo = 5
        case componentvideo = 6
        case dvi = 7
        case airplay = 8
        case usb = 9
        case application = 10
    }

    public enum IsConfigured: UInt8, CharacteristicValueType {
        case notconfigured = 0
        case configured = 1
    }

    public enum LeakDetected: UInt8, CharacteristicValueType {
        case leakNotDetected = 0
        case leakDetected = 1
    }

    public enum LockCurrentState: UInt8, CharacteristicValueType {
        case unsecured = 0
        case secured = 1
        case jammed = 2
        case unknown = 3
    }

    public enum LockTargetState: UInt8, CharacteristicValueType {
        case unsecured = 0
        case secured = 1
    }

    public enum OccupancyDetected: UInt8, CharacteristicValueType {
        case occupancyNotDetected = 0
        case occupancyDetected = 1
    }

    public enum PictureMode: UInt16, CharacteristicValueType {
        case other = 0
        case standard = 1
        case calibrated = 2
        case calibrateddark = 3
        case vivid = 4
        case game = 5
        case computer = 6
        case custom = 7
    }

    public enum PositionState: UInt8, CharacteristicValueType {
        case decreasing = 0
        case increasing = 1
        case stopped = 2
    }

    public enum PowerModeSelection: UInt8, CharacteristicValueType {
        case show = 0
        case hide = 1
    }

    public enum RemoteKey: UInt8, CharacteristicValueType {
        case rewind = 0
        case fastforward = 1
        case nexttrack = 2
        case previoustrack = 3
        case arrowup = 4
        case arrowdown = 5
        case arrowleft = 6
        case arrowright = 7
        case select = 8
        case back = 9
        case exit = 10
        case playpause = 11
        case information = 15
    }

    public enum RotationDirection: Int, CharacteristicValueType {
        case clockwise = 0
        case counterclockwise = 1
    }

    public enum SecuritySystemCurrentState: UInt8, CharacteristicValueType {
        case stayArm = 0
        case awayArm = 1
        case nightArm = 2
        case disarm = 3
        case alarmTriggered = 4
    }

    public enum SecuritySystemTargetState: UInt8, CharacteristicValueType {
        case stayArm = 0
        case awayArm = 1
        case nightArm = 2
        case disarm = 3
    }

    public enum SleepDiscoveryMode: UInt8, CharacteristicValueType {
        case notdiscoverable = 0
        case alwaysdiscoverable = 1
    }

    public enum SmokeDetected: UInt8, CharacteristicValueType {
        case smokenotdetected = 0
        case smokedetected = 1
    }

    public enum StatusLowBattery: UInt8, CharacteristicValueType {
        case batteryNormal = 0
        case batteryLow = 1
    }

    public enum TargetAirPurifierState: UInt8, CharacteristicValueType {
        case manual = 0
        case auto = 1
    }

    public enum TargetDoorState: UInt8, CharacteristicValueType {
        case open = 0
        case closed = 1
    }

    public enum TargetFanState: UInt8, CharacteristicValueType {
        case manual = 0
        case auto = 1
    }

    public enum TargetHeaterCoolerState: UInt8, CharacteristicValueType {
        case auto = 0
        case heatAuto = 1
        case coolAuto = 2
    }

    public enum TargetHeatingCoolingState: UInt8, CharacteristicValueType {
        case off = 0
        case heat = 1
        case cool = 2
        case auto = 3
    }

    public enum TargetHumidifierDehumidifierState: UInt8, CharacteristicValueType {
        case auto = 0
        case humidifyAuto = 1
        case dehumidifyAuto = 2
    }

    public enum TargetMediaState: UInt8, CharacteristicValueType {
        case play = 0
        case pause = 1
        case stop = 2
    }

    public enum TargetVisibilityState: UInt8, CharacteristicValueType {
        case shown = 0
        case hidden = 1
    }

    public enum TemperatureDisplayUnits: UInt8, CharacteristicValueType {
        case celcius = 0
        case fahrenheit = 1
    }

    public enum VolumeControlType: UInt8, CharacteristicValueType {
        case none = 0
        case relative = 1
        case relativewithcurrent = 2
        case absolute = 3
    }

    public enum VolumeSelector: UInt8, CharacteristicValueType {
        case increment = 0
        case decrement = 1
    }

}

extension Service {
    open class AccessoryRuntimeInformationBase: Service {
        // Required Characteristics
        public let ping: GenericCharacteristic<Data>

        // Optional Characteristics
        public let heartBeat: GenericCharacteristic<UInt32>?
        public let sleepInterval: GenericCharacteristic<UInt32>?

        public init(characteristics: [AnyCharacteristic] = []) {
            var unwrapped = characteristics.map { $0.wrapped }
            ping = getOrCreateAppend(
                type: .ping,
                characteristics: &unwrapped,
                generator: { PredefinedCharacteristic.ping() })
            heartBeat = get(type: .heartBeat, characteristics: unwrapped)
            sleepInterval = get(type: .sleepInterval, characteristics: unwrapped)
            super.init(type: .accessoryRuntimeInformation, characteristics: unwrapped)
        }
    }

    open class AirPurifierBase: Service {
        // Required Characteristics
        public let active: GenericCharacteristic<Enums.Active>
        public let currentAirPurifierState: GenericCharacteristic<Enums.CurrentAirPurifierState>
        public let targetAirPurifierState: GenericCharacteristic<Enums.TargetAirPurifierState>

        // Optional Characteristics
        public let lockPhysicalControls: GenericCharacteristic<UInt8>?
        public let name: GenericCharacteristic<String>?
        public let rotationSpeed: GenericCharacteristic<Float>?
        public let swingMode: GenericCharacteristic<UInt8>?

        public init(characteristics: [AnyCharacteristic] = []) {
            var unwrapped = characteristics.map { $0.wrapped }
            active = getOrCreateAppend(
                type: .active,
                characteristics: &unwrapped,
                generator: { PredefinedCharacteristic.active() })
            currentAirPurifierState = getOrCreateAppend(
                type: .currentAirPurifierState,
                characteristics: &unwrapped,
                generator: { PredefinedCharacteristic.currentAirPurifierState() })
            targetAirPurifierState = getOrCreateAppend(
                type: .targetAirPurifierState,
                characteristics: &unwrapped,
                generator: { PredefinedCharacteristic.targetAirPurifierState() })
            lockPhysicalControls = get(type: .lockPhysicalControls, characteristics: unwrapped)
            name = get(type: .name, characteristics: unwrapped)
            rotationSpeed = get(type: .rotationSpeed, characteristics: unwrapped)
            swingMode = get(type: .swingMode, characteristics: unwrapped)
            super.init(type: .airPurifier, characteristics: unwrapped)
        }
    }

    open class AirQualitySensorBase: Service {
        // Required Characteristics
        public let currentAirQuality: GenericCharacteristic<Enums.CurrentAirQuality>

        // Optional Characteristics
        public let nitrogenDioxideDensity: GenericCharacteristic<Float>?
        public let ozoneDensity: GenericCharacteristic<Float>?
        public let pm10Density: GenericCharacteristic<Float>?
        public let pm2_5Density: GenericCharacteristic<Float>?
        public let sulphurDioxideDensity: GenericCharacteristic<Float>?
        public let volatileOrganicCompoundDensity: GenericCharacteristic<Float>?
        public let name: GenericCharacteristic<String>?
        public let statusActive: GenericCharacteristic<Bool>?
        public let statusFault: GenericCharacteristic<UInt8>?
        public let statusLowBattery: GenericCharacteristic<Enums.StatusLowBattery>?
        public let statusTampered: GenericCharacteristic<UInt8>?

        public init(characteristics: [AnyCharacteristic] = []) {
            var unwrapped = characteristics.map { $0.wrapped }
            currentAirQuality = getOrCreateAppend(
                type: .currentAirQuality,
                characteristics: &unwrapped,
                generator: { PredefinedCharacteristic.currentAirQuality() })
            nitrogenDioxideDensity = get(type: .nitrogenDioxideDensity, characteristics: unwrapped)
            ozoneDensity = get(type: .ozoneDensity, characteristics: unwrapped)
            pm10Density = get(type: .pm10Density, characteristics: unwrapped)
            pm2_5Density = get(type: .pm2_5Density, characteristics: unwrapped)
            sulphurDioxideDensity = get(type: .sulphurDioxideDensity, characteristics: unwrapped)
            volatileOrganicCompoundDensity = get(type: .volatileOrganicCompoundDensity, characteristics: unwrapped)
            name = get(type: .name, characteristics: unwrapped)
            statusActive = get(type: .statusActive, characteristics: unwrapped)
            statusFault = get(type: .statusFault, characteristics: unwrapped)
            statusLowBattery = get(type: .statusLowBattery, characteristics: unwrapped)
            statusTampered = get(type: .statusTampered, characteristics: unwrapped)
            super.init(type: .airQualitySensor, characteristics: unwrapped)
        }
    }

    open class BatteryBase: Service {
        // Required Characteristics
        public let statusLowBattery: GenericCharacteristic<Enums.StatusLowBattery>

        // Optional Characteristics
        public let batteryLevel: GenericCharacteristic<UInt8>?
        public let chargingState: GenericCharacteristic<Enums.ChargingState>?
        public let name: GenericCharacteristic<String>?

        public init(characteristics: [AnyCharacteristic] = []) {
            var unwrapped = characteristics.map { $0.wrapped }
            statusLowBattery = getOrCreateAppend(
                type: .statusLowBattery,
                characteristics: &unwrapped,
                generator: { PredefinedCharacteristic.statusLowBattery() })
            batteryLevel = get(type: .batteryLevel, characteristics: unwrapped)
            chargingState = get(type: .chargingState, characteristics: unwrapped)
            name = get(type: .name, characteristics: unwrapped)
            super.init(type: .battery, characteristics: unwrapped)
        }
    }

    open class CarbonDioxideSensorBase: Service {
        // Required Characteristics
        public let carbonDioxideDetected: GenericCharacteristic<Enums.CarbonDioxideDetected>

        // Optional Characteristics
        public let carbonDioxideLevel: GenericCharacteristic<Float>?
        public let carbonDioxidePeakLevel: GenericCharacteristic<Float>?
        public let name: GenericCharacteristic<String>?
        public let statusActive: GenericCharacteristic<Bool>?
        public let statusFault: GenericCharacteristic<UInt8>?
        public let statusLowBattery: GenericCharacteristic<Enums.StatusLowBattery>?
        public let statusTampered: GenericCharacteristic<UInt8>?

        public init(characteristics: [AnyCharacteristic] = []) {
            var unwrapped = characteristics.map { $0.wrapped }
            carbonDioxideDetected = getOrCreateAppend(
                type: .carbonDioxideDetected,
                characteristics: &unwrapped,
                generator: { PredefinedCharacteristic.carbonDioxideDetected() })
            carbonDioxideLevel = get(type: .carbonDioxideLevel, characteristics: unwrapped)
            carbonDioxidePeakLevel = get(type: .carbonDioxidePeakLevel, characteristics: unwrapped)
            name = get(type: .name, characteristics: unwrapped)
            statusActive = get(type: .statusActive, characteristics: unwrapped)
            statusFault = get(type: .statusFault, characteristics: unwrapped)
            statusLowBattery = get(type: .statusLowBattery, characteristics: unwrapped)
            statusTampered = get(type: .statusTampered, characteristics: unwrapped)
            super.init(type: .carbonDioxideSensor, characteristics: unwrapped)
        }
    }

    open class CarbonMonoxideSensorBase: Service {
        // Required Characteristics
        public let carbonMonoxideDetected: GenericCharacteristic<UInt8>

        // Optional Characteristics
        public let carbonMonoxideLevel: GenericCharacteristic<Float>?
        public let carbonMonoxidePeakLevel: GenericCharacteristic<Float>?
        public let name: GenericCharacteristic<String>?
        public let statusActive: GenericCharacteristic<Bool>?
        public let statusFault: GenericCharacteristic<UInt8>?
        public let statusLowBattery: GenericCharacteristic<Enums.StatusLowBattery>?
        public let statusTampered: GenericCharacteristic<UInt8>?

        public init(characteristics: [AnyCharacteristic] = []) {
            var unwrapped = characteristics.map { $0.wrapped }
            carbonMonoxideDetected = getOrCreateAppend(
                type: .carbonMonoxideDetected,
                characteristics: &unwrapped,
                generator: { PredefinedCharacteristic.carbonMonoxideDetected() })
            carbonMonoxideLevel = get(type: .carbonMonoxideLevel, characteristics: unwrapped)
            carbonMonoxidePeakLevel = get(type: .carbonMonoxidePeakLevel, characteristics: unwrapped)
            name = get(type: .name, characteristics: unwrapped)
            statusActive = get(type: .statusActive, characteristics: unwrapped)
            statusFault = get(type: .statusFault, characteristics: unwrapped)
            statusLowBattery = get(type: .statusLowBattery, characteristics: unwrapped)
            statusTampered = get(type: .statusTampered, characteristics: unwrapped)
            super.init(type: .carbonMonoxideSensor, characteristics: unwrapped)
        }
    }

    open class ContactSensorBase: Service {
        // Required Characteristics
        public let contactSensorState: GenericCharacteristic<Enums.ContactSensorState>

        // Optional Characteristics
        public let name: GenericCharacteristic<String>?
        public let statusActive: GenericCharacteristic<Bool>?
        public let statusFault: GenericCharacteristic<UInt8>?
        public let statusLowBattery: GenericCharacteristic<Enums.StatusLowBattery>?
        public let statusTampered: GenericCharacteristic<UInt8>?

        public init(characteristics: [AnyCharacteristic] = []) {
            var unwrapped = characteristics.map { $0.wrapped }
            contactSensorState = getOrCreateAppend(
                type: .contactSensorState,
                characteristics: &unwrapped,
                generator: { PredefinedCharacteristic.contactSensorState() })
            name = get(type: .name, characteristics: unwrapped)
            statusActive = get(type: .statusActive, characteristics: unwrapped)
            statusFault = get(type: .statusFault, characteristics: unwrapped)
            statusLowBattery = get(type: .statusLowBattery, characteristics: unwrapped)
            statusTampered = get(type: .statusTampered, characteristics: unwrapped)
            super.init(type: .contactSensor, characteristics: unwrapped)
        }
    }

    open class DiagnosticsBase: Service {
        // Required Characteristics
        public let supportedDiagnosticsSnapshot: GenericCharacteristic<Data>

        // Optional Characteristics

        public init(characteristics: [AnyCharacteristic] = []) {
            var unwrapped = characteristics.map { $0.wrapped }
            supportedDiagnosticsSnapshot = getOrCreateAppend(
                type: .supportedDiagnosticsSnapshot,
                characteristics: &unwrapped,
                generator: { PredefinedCharacteristic.supportedDiagnosticsSnapshot() })
            super.init(type: .diagnostics, characteristics: unwrapped)
        }
    }

    open class DoorBase: Service {
        // Required Characteristics
        public let currentPosition: GenericCharacteristic<UInt8>
        public let positionState: GenericCharacteristic<Enums.PositionState>
        public let targetPosition: GenericCharacteristic<UInt8>

        // Optional Characteristics
        public let name: GenericCharacteristic<String>?
        public let obstructionDetected: GenericCharacteristic<Bool>?
        public let holdPosition: GenericCharacteristic<Bool?>?

        public init(characteristics: [AnyCharacteristic] = []) {
            var unwrapped = characteristics.map { $0.wrapped }
            currentPosition = getOrCreateAppend(
                type: .currentPosition,
                characteristics: &unwrapped,
                generator: { PredefinedCharacteristic.currentPosition() })
            positionState = getOrCreateAppend(
                type: .positionState,
                characteristics: &unwrapped,
                generator: { PredefinedCharacteristic.positionState() })
            targetPosition = getOrCreateAppend(
                type: .targetPosition,
                characteristics: &unwrapped,
                generator: { PredefinedCharacteristic.targetPosition() })
            name = get(type: .name, characteristics: unwrapped)
            obstructionDetected = get(type: .obstructionDetected, characteristics: unwrapped)
            holdPosition = get(type: .holdPosition, characteristics: unwrapped)
            super.init(type: .door, characteristics: unwrapped)
        }
    }

    open class DoorbellBase: Service {
        // Required Characteristics
        public let programmableSwitchEvent: GenericCharacteristic<UInt8>

        // Optional Characteristics
        public let brightness: GenericCharacteristic<Int>?
        public let mute: GenericCharacteristic<Bool>?
        public let name: GenericCharacteristic<String>?
        public let operatingStateResponse: GenericCharacteristic<Data>?
        public let volume: GenericCharacteristic<UInt8>?

        public init(characteristics: [AnyCharacteristic] = []) {
            var unwrapped = characteristics.map { $0.wrapped }
            programmableSwitchEvent = getOrCreateAppend(
                type: .programmableSwitchEvent,
                characteristics: &unwrapped,
                generator: { PredefinedCharacteristic.programmableSwitchEvent() })
            brightness = get(type: .brightness, characteristics: unwrapped)
            mute = get(type: .mute, characteristics: unwrapped)
            name = get(type: .name, characteristics: unwrapped)
            operatingStateResponse = get(type: .operatingStateResponse, characteristics: unwrapped)
            volume = get(type: .volume, characteristics: unwrapped)
            super.init(type: .doorbell, characteristics: unwrapped)
        }
    }

    open class FanBase: Service {
        // Required Characteristics
        public let powerState: GenericCharacteristic<Bool>

        // Optional Characteristics
        public let name: GenericCharacteristic<String>?
        public let rotationDirection: GenericCharacteristic<Enums.RotationDirection>?
        public let rotationSpeed: GenericCharacteristic<Float>?

        public init(characteristics: [AnyCharacteristic] = []) {
            var unwrapped = characteristics.map { $0.wrapped }
            powerState = getOrCreateAppend(
                type: .powerState,
                characteristics: &unwrapped,
                generator: { PredefinedCharacteristic.powerState() })
            name = get(type: .name, characteristics: unwrapped)
            rotationDirection = get(type: .rotationDirection, characteristics: unwrapped)
            rotationSpeed = get(type: .rotationSpeed, characteristics: unwrapped)
            super.init(type: .fan, characteristics: unwrapped)
        }
    }

    open class FanV2Base: Service {
        // Required Characteristics
        public let active: GenericCharacteristic<Enums.Active>

        // Optional Characteristics
        public let currentFanState: GenericCharacteristic<Enums.CurrentFanState>?
        public let targetFanState: GenericCharacteristic<Enums.TargetFanState>?
        public let lockPhysicalControls: GenericCharacteristic<UInt8>?
        public let name: GenericCharacteristic<String>?
        public let rotationDirection: GenericCharacteristic<Enums.RotationDirection>?
        public let rotationSpeed: GenericCharacteristic<Float>?
        public let swingMode: GenericCharacteristic<UInt8>?

        public init(characteristics: [AnyCharacteristic] = []) {
            var unwrapped = characteristics.map { $0.wrapped }
            active = getOrCreateAppend(
                type: .active,
                characteristics: &unwrapped,
                generator: { PredefinedCharacteristic.active() })
            currentFanState = get(type: .currentFanState, characteristics: unwrapped)
            targetFanState = get(type: .targetFanState, characteristics: unwrapped)
            lockPhysicalControls = get(type: .lockPhysicalControls, characteristics: unwrapped)
            name = get(type: .name, characteristics: unwrapped)
            rotationDirection = get(type: .rotationDirection, characteristics: unwrapped)
            rotationSpeed = get(type: .rotationSpeed, characteristics: unwrapped)
            swingMode = get(type: .swingMode, characteristics: unwrapped)
            super.init(type: .fanV2, characteristics: unwrapped)
        }
    }

    open class FaucetBase: Service {
        // Required Characteristics
        public let active: GenericCharacteristic<Enums.Active>

        // Optional Characteristics
        public let name: GenericCharacteristic<String>?
        public let statusFault: GenericCharacteristic<UInt8>?

        public init(characteristics: [AnyCharacteristic] = []) {
            var unwrapped = characteristics.map { $0.wrapped }
            active = getOrCreateAppend(
                type: .active,
                characteristics: &unwrapped,
                generator: { PredefinedCharacteristic.active() })
            name = get(type: .name, characteristics: unwrapped)
            statusFault = get(type: .statusFault, characteristics: unwrapped)
            super.init(type: .faucet, characteristics: unwrapped)
        }
    }

    open class FilterMaintenanceBase: Service {
        // Required Characteristics
        public let filterChangeIndication: GenericCharacteristic<Enums.FilterChangeIndication>

        // Optional Characteristics
        public let filterLifeLevel: GenericCharacteristic<Float>?
        public let filterResetChangeIndication: GenericCharacteristic<UInt8?>?
        public let name: GenericCharacteristic<String>?

        public init(characteristics: [AnyCharacteristic] = []) {
            var unwrapped = characteristics.map { $0.wrapped }
            filterChangeIndication = getOrCreateAppend(
                type: .filterChangeIndication,
                characteristics: &unwrapped,
                generator: { PredefinedCharacteristic.filterChangeIndication() })
            filterLifeLevel = get(type: .filterLifeLevel, characteristics: unwrapped)
            filterResetChangeIndication = get(type: .filterResetChangeIndication, characteristics: unwrapped)
            name = get(type: .name, characteristics: unwrapped)
            super.init(type: .filterMaintenance, characteristics: unwrapped)
        }
    }

    open class GarageDoorOpenerBase: Service {
        // Required Characteristics
        public let currentDoorState: GenericCharacteristic<Enums.CurrentDoorState>
        public let targetDoorState: GenericCharacteristic<Enums.TargetDoorState>
        public let obstructionDetected: GenericCharacteristic<Bool>

        // Optional Characteristics
        public let lockCurrentState: GenericCharacteristic<Enums.LockCurrentState>?
        public let lockTargetState: GenericCharacteristic<Enums.LockTargetState>?
        public let name: GenericCharacteristic<String>?

        public init(characteristics: [AnyCharacteristic] = []) {
            var unwrapped = characteristics.map { $0.wrapped }
            currentDoorState = getOrCreateAppend(
                type: .currentDoorState,
                characteristics: &unwrapped,
                generator: { PredefinedCharacteristic.currentDoorState() })
            targetDoorState = getOrCreateAppend(
                type: .targetDoorState,
                characteristics: &unwrapped,
                generator: { PredefinedCharacteristic.targetDoorState() })
            obstructionDetected = getOrCreateAppend(
                type: .obstructionDetected,
                characteristics: &unwrapped,
                generator: { PredefinedCharacteristic.obstructionDetected() })
            lockCurrentState = get(type: .lockCurrentState, characteristics: unwrapped)
            lockTargetState = get(type: .lockTargetState, characteristics: unwrapped)
            name = get(type: .name, characteristics: unwrapped)
            super.init(type: .garageDoorOpener, characteristics: unwrapped)
        }
    }

    open class HeaterCoolerBase: Service {
        // Required Characteristics
        public let active: GenericCharacteristic<Enums.Active>
        public let currentHeaterCoolerState: GenericCharacteristic<Enums.CurrentHeaterCoolerState>
        public let targetHeaterCoolerState: GenericCharacteristic<Enums.TargetHeaterCoolerState>
        public let currentTemperature: GenericCharacteristic<Float>

        // Optional Characteristics
        public let lockPhysicalControls: GenericCharacteristic<UInt8>?
        public let name: GenericCharacteristic<String>?
        public let rotationSpeed: GenericCharacteristic<Float>?
        public let swingMode: GenericCharacteristic<UInt8>?
        public let coolingThresholdTemperature: GenericCharacteristic<Float>?
        public let heatingThresholdTemperature: GenericCharacteristic<Float>?
        public let temperatureDisplayUnits: GenericCharacteristic<Enums.TemperatureDisplayUnits>?

        public init(characteristics: [AnyCharacteristic] = []) {
            var unwrapped = characteristics.map { $0.wrapped }
            active = getOrCreateAppend(
                type: .active,
                characteristics: &unwrapped,
                generator: { PredefinedCharacteristic.active() })
            currentHeaterCoolerState = getOrCreateAppend(
                type: .currentHeaterCoolerState,
                characteristics: &unwrapped,
                generator: { PredefinedCharacteristic.currentHeaterCoolerState() })
            targetHeaterCoolerState = getOrCreateAppend(
                type: .targetHeaterCoolerState,
                characteristics: &unwrapped,
                generator: { PredefinedCharacteristic.targetHeaterCoolerState() })
            currentTemperature = getOrCreateAppend(
                type: .currentTemperature,
                characteristics: &unwrapped,
                generator: { PredefinedCharacteristic.currentTemperature() })
            lockPhysicalControls = get(type: .lockPhysicalControls, characteristics: unwrapped)
            name = get(type: .name, characteristics: unwrapped)
            rotationSpeed = get(type: .rotationSpeed, characteristics: unwrapped)
            swingMode = get(type: .swingMode, characteristics: unwrapped)
            coolingThresholdTemperature = get(type: .coolingThresholdTemperature, characteristics: unwrapped)
            heatingThresholdTemperature = get(type: .heatingThresholdTemperature, characteristics: unwrapped)
            temperatureDisplayUnits = get(type: .temperatureDisplayUnits, characteristics: unwrapped)
            super.init(type: .heaterCooler, characteristics: unwrapped)
        }
    }

    open class HumidifierDehumidifierBase: Service {
        // Required Characteristics
        public let active: GenericCharacteristic<Enums.Active>
        public let currentHumidifierDehumidifierState: GenericCharacteristic<Enums.CurrentHumidifierDehumidifierState>
        public let targetHumidifierDehumidifierState: GenericCharacteristic<Enums.TargetHumidifierDehumidifierState>
        public let currentRelativeHumidity: GenericCharacteristic<Float>

        // Optional Characteristics
        public let lockPhysicalControls: GenericCharacteristic<UInt8>?
        public let name: GenericCharacteristic<String>?
        public let relativeHumidityDehumidifierThreshold: GenericCharacteristic<Float>?
        public let relativeHumidityHumidifierThreshold: GenericCharacteristic<Float>?
        public let rotationSpeed: GenericCharacteristic<Float>?
        public let swingMode: GenericCharacteristic<UInt8>?
        public let currentWaterLevel: GenericCharacteristic<Float>?

        public init(characteristics: [AnyCharacteristic] = []) {
            var unwrapped = characteristics.map { $0.wrapped }
            active = getOrCreateAppend(
                type: .active,
                characteristics: &unwrapped,
                generator: { PredefinedCharacteristic.active() })
            currentHumidifierDehumidifierState = getOrCreateAppend(
                type: .currentHumidifierDehumidifierState,
                characteristics: &unwrapped,
                generator: { PredefinedCharacteristic.currentHumidifierDehumidifierState() })
            targetHumidifierDehumidifierState = getOrCreateAppend(
                type: .targetHumidifierDehumidifierState,
                characteristics: &unwrapped,
                generator: { PredefinedCharacteristic.targetHumidifierDehumidifierState() })
            currentRelativeHumidity = getOrCreateAppend(
                type: .currentRelativeHumidity,
                characteristics: &unwrapped,
                generator: { PredefinedCharacteristic.currentRelativeHumidity() })
            lockPhysicalControls = get(type: .lockPhysicalControls, characteristics: unwrapped)
            name = get(type: .name, characteristics: unwrapped)
            relativeHumidityDehumidifierThreshold = get(type: .relativeHumidityDehumidifierThreshold, characteristics: unwrapped)
            relativeHumidityHumidifierThreshold = get(type: .relativeHumidityHumidifierThreshold, characteristics: unwrapped)
            rotationSpeed = get(type: .rotationSpeed, characteristics: unwrapped)
            swingMode = get(type: .swingMode, characteristics: unwrapped)
            currentWaterLevel = get(type: .currentWaterLevel, characteristics: unwrapped)
            super.init(type: .humidifierDehumidifier, characteristics: unwrapped)
        }
    }

    open class HumiditySensorBase: Service {
        // Required Characteristics
        public let currentRelativeHumidity: GenericCharacteristic<Float>

        // Optional Characteristics
        public let name: GenericCharacteristic<String>?
        public let statusActive: GenericCharacteristic<Bool>?
        public let statusFault: GenericCharacteristic<UInt8>?
        public let statusLowBattery: GenericCharacteristic<Enums.StatusLowBattery>?
        public let statusTampered: GenericCharacteristic<UInt8>?

        public init(characteristics: [AnyCharacteristic] = []) {
            var unwrapped = characteristics.map { $0.wrapped }
            currentRelativeHumidity = getOrCreateAppend(
                type: .currentRelativeHumidity,
                characteristics: &unwrapped,
                generator: { PredefinedCharacteristic.currentRelativeHumidity() })
            name = get(type: .name, characteristics: unwrapped)
            statusActive = get(type: .statusActive, characteristics: unwrapped)
            statusFault = get(type: .statusFault, characteristics: unwrapped)
            statusLowBattery = get(type: .statusLowBattery, characteristics: unwrapped)
            statusTampered = get(type: .statusTampered, characteristics: unwrapped)
            super.init(type: .humiditySensor, characteristics: unwrapped)
        }
    }

    open class InfoBase: Service {
        // Required Characteristics
        public let identify: GenericCharacteristic<Bool?>
        public let manufacturer: GenericCharacteristic<String>
        public let model: GenericCharacteristic<String>
        public let name: GenericCharacteristic<String>
        public let serialNumber: GenericCharacteristic<String>

        // Optional Characteristics
        public let accessoryFlags: GenericCharacteristic<UInt32>?
        public let applicationMatchingIdentifier: GenericCharacteristic<Data>?
        public let configuredName: GenericCharacteristic<String>?
        public let firmwareRevision: GenericCharacteristic<String>?
        public let hardwareRevision: GenericCharacteristic<String>?
        public let softwareRevision: GenericCharacteristic<String>?
        public let productData: GenericCharacteristic<Data>?

        public init(characteristics: [AnyCharacteristic] = []) {
            var unwrapped = characteristics.map { $0.wrapped }
            identify = getOrCreateAppend(
                type: .identify,
                characteristics: &unwrapped,
                generator: { PredefinedCharacteristic.identify() })
            manufacturer = getOrCreateAppend(
                type: .manufacturer,
                characteristics: &unwrapped,
                generator: { PredefinedCharacteristic.manufacturer() })
            model = getOrCreateAppend(
                type: .model,
                characteristics: &unwrapped,
                generator: { PredefinedCharacteristic.model() })
            name = getOrCreateAppend(
                type: .name,
                characteristics: &unwrapped,
                generator: { PredefinedCharacteristic.name() })
            serialNumber = getOrCreateAppend(
                type: .serialNumber,
                characteristics: &unwrapped,
                generator: { PredefinedCharacteristic.serialNumber() })
            accessoryFlags = get(type: .accessoryFlags, characteristics: unwrapped)
            applicationMatchingIdentifier = get(type: .applicationMatchingIdentifier, characteristics: unwrapped)
            configuredName = get(type: .configuredName, characteristics: unwrapped)
            firmwareRevision = get(type: .firmwareRevision, characteristics: unwrapped)
            hardwareRevision = get(type: .hardwareRevision, characteristics: unwrapped)
            softwareRevision = get(type: .softwareRevision, characteristics: unwrapped)
            productData = get(type: .productData, characteristics: unwrapped)
            super.init(type: .info, characteristics: unwrapped)
        }
    }

    open class InputSourceBase: Service {
        // Required Characteristics
        public let configuredName: GenericCharacteristic<String>
        public let inputSourceType: GenericCharacteristic<Enums.InputSourceType>
        public let isConfigured: GenericCharacteristic<Enums.IsConfigured>
        public let name: GenericCharacteristic<String>
        public let currentVisibilityState: GenericCharacteristic<Enums.CurrentVisibilityState>

        // Optional Characteristics
        public let identifier: GenericCharacteristic<UInt32>?
        public let inputDeviceType: GenericCharacteristic<Enums.InputDeviceType>?
        public let targetVisibilityState: GenericCharacteristic<Enums.TargetVisibilityState>?

        public init(characteristics: [AnyCharacteristic] = []) {
            var unwrapped = characteristics.map { $0.wrapped }
            configuredName = getOrCreateAppend(
                type: .configuredName,
                characteristics: &unwrapped,
                generator: { PredefinedCharacteristic.configuredName() })
            inputSourceType = getOrCreateAppend(
                type: .inputSourceType,
                characteristics: &unwrapped,
                generator: { PredefinedCharacteristic.inputSourceType() })
            isConfigured = getOrCreateAppend(
                type: .isConfigured,
                characteristics: &unwrapped,
                generator: { PredefinedCharacteristic.isConfigured() })
            name = getOrCreateAppend(
                type: .name,
                characteristics: &unwrapped,
                generator: { PredefinedCharacteristic.name() })
            currentVisibilityState = getOrCreateAppend(
                type: .currentVisibilityState,
                characteristics: &unwrapped,
                generator: { PredefinedCharacteristic.currentVisibilityState() })
            identifier = get(type: .identifier, characteristics: unwrapped)
            inputDeviceType = get(type: .inputDeviceType, characteristics: unwrapped)
            targetVisibilityState = get(type: .targetVisibilityState, characteristics: unwrapped)
            super.init(type: .inputSource, characteristics: unwrapped)
        }
    }

    open class IrrigationSystemBase: Service {
        // Required Characteristics
        public let active: GenericCharacteristic<Enums.Active>
        public let programMode: GenericCharacteristic<UInt8>
        public let inUse: GenericCharacteristic<UInt8>

        // Optional Characteristics
        public let remainingDuration: GenericCharacteristic<UInt32>?
        public let name: GenericCharacteristic<String>?
        public let statusFault: GenericCharacteristic<UInt8>?

        public init(characteristics: [AnyCharacteristic] = []) {
            var unwrapped = characteristics.map { $0.wrapped }
            active = getOrCreateAppend(
                type: .active,
                characteristics: &unwrapped,
                generator: { PredefinedCharacteristic.active() })
            programMode = getOrCreateAppend(
                type: .programMode,
                characteristics: &unwrapped,
                generator: { PredefinedCharacteristic.programMode() })
            inUse = getOrCreateAppend(
                type: .inUse,
                characteristics: &unwrapped,
                generator: { PredefinedCharacteristic.inUse() })
            remainingDuration = get(type: .remainingDuration, characteristics: unwrapped)
            name = get(type: .name, characteristics: unwrapped)
            statusFault = get(type: .statusFault, characteristics: unwrapped)
            super.init(type: .irrigationSystem, characteristics: unwrapped)
        }
    }

    open class LabelBase: Service {
        // Required Characteristics
        public let labelNamespace: GenericCharacteristic<UInt8>

        // Optional Characteristics

        public init(characteristics: [AnyCharacteristic] = []) {
            var unwrapped = characteristics.map { $0.wrapped }
            labelNamespace = getOrCreateAppend(
                type: .labelNamespace,
                characteristics: &unwrapped,
                generator: { PredefinedCharacteristic.labelNamespace() })
            super.init(type: .label, characteristics: unwrapped)
        }
    }

    open class LeakSensorBase: Service {
        // Required Characteristics
        public let leakDetected: GenericCharacteristic<Enums.LeakDetected>

        // Optional Characteristics
        public let name: GenericCharacteristic<String>?
        public let statusActive: GenericCharacteristic<Bool>?
        public let statusFault: GenericCharacteristic<UInt8>?
        public let statusLowBattery: GenericCharacteristic<Enums.StatusLowBattery>?
        public let statusTampered: GenericCharacteristic<UInt8>?

        public init(characteristics: [AnyCharacteristic] = []) {
            var unwrapped = characteristics.map { $0.wrapped }
            leakDetected = getOrCreateAppend(
                type: .leakDetected,
                characteristics: &unwrapped,
                generator: { PredefinedCharacteristic.leakDetected() })
            name = get(type: .name, characteristics: unwrapped)
            statusActive = get(type: .statusActive, characteristics: unwrapped)
            statusFault = get(type: .statusFault, characteristics: unwrapped)
            statusLowBattery = get(type: .statusLowBattery, characteristics: unwrapped)
            statusTampered = get(type: .statusTampered, characteristics: unwrapped)
            super.init(type: .leakSensor, characteristics: unwrapped)
        }
    }

    open class LightSensorBase: Service {
        // Required Characteristics
        public let currentLightLevel: GenericCharacteristic<Float>

        // Optional Characteristics
        public let name: GenericCharacteristic<String>?
        public let statusActive: GenericCharacteristic<Bool>?
        public let statusFault: GenericCharacteristic<UInt8>?
        public let statusLowBattery: GenericCharacteristic<Enums.StatusLowBattery>?
        public let statusTampered: GenericCharacteristic<UInt8>?

        public init(characteristics: [AnyCharacteristic] = []) {
            var unwrapped = characteristics.map { $0.wrapped }
            currentLightLevel = getOrCreateAppend(
                type: .currentLightLevel,
                characteristics: &unwrapped,
                generator: { PredefinedCharacteristic.currentLightLevel() })
            name = get(type: .name, characteristics: unwrapped)
            statusActive = get(type: .statusActive, characteristics: unwrapped)
            statusFault = get(type: .statusFault, characteristics: unwrapped)
            statusLowBattery = get(type: .statusLowBattery, characteristics: unwrapped)
            statusTampered = get(type: .statusTampered, characteristics: unwrapped)
            super.init(type: .lightSensor, characteristics: unwrapped)
        }
    }

    open class LightbulbBase: Service {
        // Required Characteristics
        public let powerState: GenericCharacteristic<Bool>

        // Optional Characteristics
        public let brightness: GenericCharacteristic<Int>?
        public let characteristicValueActiveTransitionCount: GenericCharacteristic<UInt8>?
        public let characteristicValueTransitionControl: GenericCharacteristic<Data>?
        public let colorTemperature: GenericCharacteristic<Int>?
        public let hue: GenericCharacteristic<Float>?
        public let name: GenericCharacteristic<String>?
        public let saturation: GenericCharacteristic<Float>?
        public let supportedCharacteristicValueTransitionConfiguration: GenericCharacteristic<Data>?

        public init(characteristics: [AnyCharacteristic] = []) {
            var unwrapped = characteristics.map { $0.wrapped }
            powerState = getOrCreateAppend(
                type: .powerState,
                characteristics: &unwrapped,
                generator: { PredefinedCharacteristic.powerState() })
            brightness = get(type: .brightness, characteristics: unwrapped)
            characteristicValueActiveTransitionCount = get(type: .characteristicValueActiveTransitionCount, characteristics: unwrapped)
            characteristicValueTransitionControl = get(type: .characteristicValueTransitionControl, characteristics: unwrapped)
            colorTemperature = get(type: .colorTemperature, characteristics: unwrapped)
            hue = get(type: .hue, characteristics: unwrapped)
            name = get(type: .name, characteristics: unwrapped)
            saturation = get(type: .saturation, characteristics: unwrapped)
            supportedCharacteristicValueTransitionConfiguration = get(type: .supportedCharacteristicValueTransitionConfiguration, characteristics: unwrapped)
            super.init(type: .lightbulb, characteristics: unwrapped)
        }
    }

    open class LockManagementBase: Service {
        // Required Characteristics
        public let lockControlPoint: GenericCharacteristic<Data?>
        public let version: GenericCharacteristic<String>

        // Optional Characteristics
        public let administratorOnlyAccess: GenericCharacteristic<Bool>?
        public let audioFeedback: GenericCharacteristic<Bool>?
        public let currentDoorState: GenericCharacteristic<Enums.CurrentDoorState>?
        public let lockManagementAutoSecurityTimeout: GenericCharacteristic<UInt32>?
        public let lockLastKnownAction: GenericCharacteristic<UInt8>?
        public let logs: GenericCharacteristic<Data>?
        public let motionDetected: GenericCharacteristic<Bool>?

        public init(characteristics: [AnyCharacteristic] = []) {
            var unwrapped = characteristics.map { $0.wrapped }
            lockControlPoint = getOrCreateAppend(
                type: .lockControlPoint,
                characteristics: &unwrapped,
                generator: { PredefinedCharacteristic.lockControlPoint() })
            version = getOrCreateAppend(
                type: .version,
                characteristics: &unwrapped,
                generator: { PredefinedCharacteristic.version() })
            administratorOnlyAccess = get(type: .administratorOnlyAccess, characteristics: unwrapped)
            audioFeedback = get(type: .audioFeedback, characteristics: unwrapped)
            currentDoorState = get(type: .currentDoorState, characteristics: unwrapped)
            lockManagementAutoSecurityTimeout = get(type: .lockManagementAutoSecurityTimeout, characteristics: unwrapped)
            lockLastKnownAction = get(type: .lockLastKnownAction, characteristics: unwrapped)
            logs = get(type: .logs, characteristics: unwrapped)
            motionDetected = get(type: .motionDetected, characteristics: unwrapped)
            super.init(type: .lockManagement, characteristics: unwrapped)
        }
    }

    open class LockMechanismBase: Service {
        // Required Characteristics
        public let lockCurrentState: GenericCharacteristic<Enums.LockCurrentState>
        public let lockTargetState: GenericCharacteristic<Enums.LockTargetState>

        // Optional Characteristics
        public let name: GenericCharacteristic<String>?

        public init(characteristics: [AnyCharacteristic] = []) {
            var unwrapped = characteristics.map { $0.wrapped }
            lockCurrentState = getOrCreateAppend(
                type: .lockCurrentState,
                characteristics: &unwrapped,
                generator: { PredefinedCharacteristic.lockCurrentState() })
            lockTargetState = getOrCreateAppend(
                type: .lockTargetState,
                characteristics: &unwrapped,
                generator: { PredefinedCharacteristic.lockTargetState() })
            name = get(type: .name, characteristics: unwrapped)
            super.init(type: .lockMechanism, characteristics: unwrapped)
        }
    }

    open class MicrophoneBase: Service {
        // Required Characteristics
        public let mute: GenericCharacteristic<Bool>

        // Optional Characteristics
        public let volume: GenericCharacteristic<UInt8>?

        public init(characteristics: [AnyCharacteristic] = []) {
            var unwrapped = characteristics.map { $0.wrapped }
            mute = getOrCreateAppend(
                type: .mute,
                characteristics: &unwrapped,
                generator: { PredefinedCharacteristic.mute() })
            volume = get(type: .volume, characteristics: unwrapped)
            super.init(type: .microphone, characteristics: unwrapped)
        }
    }

    open class MotionSensorBase: Service {
        // Required Characteristics
        public let motionDetected: GenericCharacteristic<Bool>

        // Optional Characteristics
        public let name: GenericCharacteristic<String>?
        public let statusActive: GenericCharacteristic<Bool>?
        public let statusFault: GenericCharacteristic<UInt8>?
        public let statusLowBattery: GenericCharacteristic<Enums.StatusLowBattery>?
        public let statusTampered: GenericCharacteristic<UInt8>?

        public init(characteristics: [AnyCharacteristic] = []) {
            var unwrapped = characteristics.map { $0.wrapped }
            motionDetected = getOrCreateAppend(
                type: .motionDetected,
                characteristics: &unwrapped,
                generator: { PredefinedCharacteristic.motionDetected() })
            name = get(type: .name, characteristics: unwrapped)
            statusActive = get(type: .statusActive, characteristics: unwrapped)
            statusFault = get(type: .statusFault, characteristics: unwrapped)
            statusLowBattery = get(type: .statusLowBattery, characteristics: unwrapped)
            statusTampered = get(type: .statusTampered, characteristics: unwrapped)
            super.init(type: .motionSensor, characteristics: unwrapped)
        }
    }

    open class OccupancySensorBase: Service {
        // Required Characteristics
        public let occupancyDetected: GenericCharacteristic<Enums.OccupancyDetected>

        // Optional Characteristics
        public let name: GenericCharacteristic<String>?
        public let statusActive: GenericCharacteristic<Bool>?
        public let statusFault: GenericCharacteristic<UInt8>?
        public let statusLowBattery: GenericCharacteristic<Enums.StatusLowBattery>?
        public let statusTampered: GenericCharacteristic<UInt8>?

        public init(characteristics: [AnyCharacteristic] = []) {
            var unwrapped = characteristics.map { $0.wrapped }
            occupancyDetected = getOrCreateAppend(
                type: .occupancyDetected,
                characteristics: &unwrapped,
                generator: { PredefinedCharacteristic.occupancyDetected() })
            name = get(type: .name, characteristics: unwrapped)
            statusActive = get(type: .statusActive, characteristics: unwrapped)
            statusFault = get(type: .statusFault, characteristics: unwrapped)
            statusLowBattery = get(type: .statusLowBattery, characteristics: unwrapped)
            statusTampered = get(type: .statusTampered, characteristics: unwrapped)
            super.init(type: .occupancySensor, characteristics: unwrapped)
        }
    }

    open class OutletBase: Service {
        // Required Characteristics
        public let powerState: GenericCharacteristic<Bool>

        // Optional Characteristics
        public let name: GenericCharacteristic<String>?
        public let outletInUse: GenericCharacteristic<Bool>?

        public init(characteristics: [AnyCharacteristic] = []) {
            var unwrapped = characteristics.map { $0.wrapped }
            powerState = getOrCreateAppend(
                type: .powerState,
                characteristics: &unwrapped,
                generator: { PredefinedCharacteristic.powerState() })
            name = get(type: .name, characteristics: unwrapped)
            outletInUse = get(type: .outletInUse, characteristics: unwrapped)
            super.init(type: .outlet, characteristics: unwrapped)
        }
    }

    open class SecuritySystemBase: Service {
        // Required Characteristics
        public let securitySystemCurrentState: GenericCharacteristic<Enums.SecuritySystemCurrentState>
        public let securitySystemTargetState: GenericCharacteristic<Enums.SecuritySystemTargetState>

        // Optional Characteristics
        public let name: GenericCharacteristic<String>?
        public let securitySystemAlarmType: GenericCharacteristic<UInt8>?
        public let statusFault: GenericCharacteristic<UInt8>?
        public let statusTampered: GenericCharacteristic<UInt8>?

        public init(characteristics: [AnyCharacteristic] = []) {
            var unwrapped = characteristics.map { $0.wrapped }
            securitySystemCurrentState = getOrCreateAppend(
                type: .securitySystemCurrentState,
                characteristics: &unwrapped,
                generator: { PredefinedCharacteristic.securitySystemCurrentState() })
            securitySystemTargetState = getOrCreateAppend(
                type: .securitySystemTargetState,
                characteristics: &unwrapped,
                generator: { PredefinedCharacteristic.securitySystemTargetState() })
            name = get(type: .name, characteristics: unwrapped)
            securitySystemAlarmType = get(type: .securitySystemAlarmType, characteristics: unwrapped)
            statusFault = get(type: .statusFault, characteristics: unwrapped)
            statusTampered = get(type: .statusTampered, characteristics: unwrapped)
            super.init(type: .securitySystem, characteristics: unwrapped)
        }
    }

    open class SlatsBase: Service {
        // Required Characteristics
        public let currentSlatState: GenericCharacteristic<Enums.CurrentSlatState>
        public let slatType: GenericCharacteristic<UInt8>

        // Optional Characteristics
        public let name: GenericCharacteristic<String>?
        public let swingMode: GenericCharacteristic<UInt8>?
        public let currentTiltAngle: GenericCharacteristic<Int>?
        public let targetTiltAngle: GenericCharacteristic<Int>?

        public init(characteristics: [AnyCharacteristic] = []) {
            var unwrapped = characteristics.map { $0.wrapped }
            currentSlatState = getOrCreateAppend(
                type: .currentSlatState,
                characteristics: &unwrapped,
                generator: { PredefinedCharacteristic.currentSlatState() })
            slatType = getOrCreateAppend(
                type: .slatType,
                characteristics: &unwrapped,
                generator: { PredefinedCharacteristic.slatType() })
            name = get(type: .name, characteristics: unwrapped)
            swingMode = get(type: .swingMode, characteristics: unwrapped)
            currentTiltAngle = get(type: .currentTiltAngle, characteristics: unwrapped)
            targetTiltAngle = get(type: .targetTiltAngle, characteristics: unwrapped)
            super.init(type: .slats, characteristics: unwrapped)
        }
    }

    open class SmokeSensorBase: Service {
        // Required Characteristics
        public let smokeDetected: GenericCharacteristic<Enums.SmokeDetected>

        // Optional Characteristics
        public let name: GenericCharacteristic<String>?
        public let statusActive: GenericCharacteristic<Bool>?
        public let statusFault: GenericCharacteristic<UInt8>?
        public let statusLowBattery: GenericCharacteristic<Enums.StatusLowBattery>?
        public let statusTampered: GenericCharacteristic<UInt8>?

        public init(characteristics: [AnyCharacteristic] = []) {
            var unwrapped = characteristics.map { $0.wrapped }
            smokeDetected = getOrCreateAppend(
                type: .smokeDetected,
                characteristics: &unwrapped,
                generator: { PredefinedCharacteristic.smokeDetected() })
            name = get(type: .name, characteristics: unwrapped)
            statusActive = get(type: .statusActive, characteristics: unwrapped)
            statusFault = get(type: .statusFault, characteristics: unwrapped)
            statusLowBattery = get(type: .statusLowBattery, characteristics: unwrapped)
            statusTampered = get(type: .statusTampered, characteristics: unwrapped)
            super.init(type: .smokeSensor, characteristics: unwrapped)
        }
    }

    open class SpeakerBase: Service {
        // Required Characteristics
        public let mute: GenericCharacteristic<Bool>

        // Optional Characteristics
        public let active: GenericCharacteristic<Enums.Active>?
        public let volume: GenericCharacteristic<UInt8>?
        public let volumeControlType: GenericCharacteristic<Enums.VolumeControlType>?
        public let volumeSelector: GenericCharacteristic<Enums.VolumeSelector?>?

        public init(characteristics: [AnyCharacteristic] = []) {
            var unwrapped = characteristics.map { $0.wrapped }
            mute = getOrCreateAppend(
                type: .mute,
                characteristics: &unwrapped,
                generator: { PredefinedCharacteristic.mute() })
            active = get(type: .active, characteristics: unwrapped)
            volume = get(type: .volume, characteristics: unwrapped)
            volumeControlType = get(type: .volumeControlType, characteristics: unwrapped)
            volumeSelector = get(type: .volumeSelector, characteristics: unwrapped)
            super.init(type: .speaker, characteristics: unwrapped)
        }
    }

    open class StatefulProgrammableSwitchBase: Service {
        // Required Characteristics
        public let programmableSwitchEvent: GenericCharacteristic<UInt8>
        public let programmableSwitchOutputState: GenericCharacteristic<UInt8>

        // Optional Characteristics
        public let name: GenericCharacteristic<String>?

        public init(characteristics: [AnyCharacteristic] = []) {
            var unwrapped = characteristics.map { $0.wrapped }
            programmableSwitchEvent = getOrCreateAppend(
                type: .programmableSwitchEvent,
                characteristics: &unwrapped,
                generator: { PredefinedCharacteristic.programmableSwitchEvent() })
            programmableSwitchOutputState = getOrCreateAppend(
                type: .programmableSwitchOutputState,
                characteristics: &unwrapped,
                generator: { PredefinedCharacteristic.programmableSwitchOutputState() })
            name = get(type: .name, characteristics: unwrapped)
            super.init(type: .statefulProgrammableSwitch, characteristics: unwrapped)
        }
    }

    open class StatelessProgrammableSwitchBase: Service {
        // Required Characteristics
        public let programmableSwitchEvent: GenericCharacteristic<UInt8>

        // Optional Characteristics
        public let name: GenericCharacteristic<String>?
        public let labelIndex: GenericCharacteristic<UInt8>?

        public init(characteristics: [AnyCharacteristic] = []) {
            var unwrapped = characteristics.map { $0.wrapped }
            programmableSwitchEvent = getOrCreateAppend(
                type: .programmableSwitchEvent,
                characteristics: &unwrapped,
                generator: { PredefinedCharacteristic.programmableSwitchEvent() })
            name = get(type: .name, characteristics: unwrapped)
            labelIndex = get(type: .labelIndex, characteristics: unwrapped)
            super.init(type: .statelessProgrammableSwitch, characteristics: unwrapped)
        }
    }

    open class SwitchBase: Service {
        // Required Characteristics
        public let powerState: GenericCharacteristic<Bool>

        // Optional Characteristics
        public let name: GenericCharacteristic<String>?

        public init(characteristics: [AnyCharacteristic] = []) {
            var unwrapped = characteristics.map { $0.wrapped }
            powerState = getOrCreateAppend(
                type: .powerState,
                characteristics: &unwrapped,
                generator: { PredefinedCharacteristic.powerState() })
            name = get(type: .name, characteristics: unwrapped)
            super.init(type: .`switch`, characteristics: unwrapped)
        }
    }

    open class TelevisionBase: Service {
        // Required Characteristics
        public let active: GenericCharacteristic<Enums.Active>
        public let activeIdentifier: GenericCharacteristic<UInt32>
        public let configuredName: GenericCharacteristic<String>
        public let remoteKey: GenericCharacteristic<Enums.RemoteKey?>
        public let sleepDiscoveryMode: GenericCharacteristic<Enums.SleepDiscoveryMode>

        // Optional Characteristics
        public let brightness: GenericCharacteristic<Int>?
        public let closedCaptions: GenericCharacteristic<Enums.ClosedCaptions>?
        public let displayOrder: GenericCharacteristic<Data>?
        public let currentMediaState: GenericCharacteristic<UInt8>?
        public let targetMediaState: GenericCharacteristic<Enums.TargetMediaState>?
        public let name: GenericCharacteristic<String>?
        public let pictureMode: GenericCharacteristic<Enums.PictureMode>?
        public let powerModeSelection: GenericCharacteristic<Enums.PowerModeSelection?>?

        public init(characteristics: [AnyCharacteristic] = []) {
            var unwrapped = characteristics.map { $0.wrapped }
            active = getOrCreateAppend(
                type: .active,
                characteristics: &unwrapped,
                generator: { PredefinedCharacteristic.active() })
            activeIdentifier = getOrCreateAppend(
                type: .activeIdentifier,
                characteristics: &unwrapped,
                generator: { PredefinedCharacteristic.activeIdentifier() })
            configuredName = getOrCreateAppend(
                type: .configuredName,
                characteristics: &unwrapped,
                generator: { PredefinedCharacteristic.configuredName() })
            remoteKey = getOrCreateAppend(
                type: .remoteKey,
                characteristics: &unwrapped,
                generator: { PredefinedCharacteristic.remoteKey() })
            sleepDiscoveryMode = getOrCreateAppend(
                type: .sleepDiscoveryMode,
                characteristics: &unwrapped,
                generator: { PredefinedCharacteristic.sleepDiscoveryMode() })
            brightness = get(type: .brightness, characteristics: unwrapped)
            closedCaptions = get(type: .closedCaptions, characteristics: unwrapped)
            displayOrder = get(type: .displayOrder, characteristics: unwrapped)
            currentMediaState = get(type: .currentMediaState, characteristics: unwrapped)
            targetMediaState = get(type: .targetMediaState, characteristics: unwrapped)
            name = get(type: .name, characteristics: unwrapped)
            pictureMode = get(type: .pictureMode, characteristics: unwrapped)
            powerModeSelection = get(type: .powerModeSelection, characteristics: unwrapped)
            super.init(type: .television, characteristics: unwrapped)
        }
    }

    open class TemperatureSensorBase: Service {
        // Required Characteristics
        public let currentTemperature: GenericCharacteristic<Float>

        // Optional Characteristics
        public let name: GenericCharacteristic<String>?
        public let statusActive: GenericCharacteristic<Bool>?
        public let statusFault: GenericCharacteristic<UInt8>?
        public let statusLowBattery: GenericCharacteristic<Enums.StatusLowBattery>?
        public let statusTampered: GenericCharacteristic<UInt8>?

        public init(characteristics: [AnyCharacteristic] = []) {
            var unwrapped = characteristics.map { $0.wrapped }
            currentTemperature = getOrCreateAppend(
                type: .currentTemperature,
                characteristics: &unwrapped,
                generator: { PredefinedCharacteristic.currentTemperature() })
            name = get(type: .name, characteristics: unwrapped)
            statusActive = get(type: .statusActive, characteristics: unwrapped)
            statusFault = get(type: .statusFault, characteristics: unwrapped)
            statusLowBattery = get(type: .statusLowBattery, characteristics: unwrapped)
            statusTampered = get(type: .statusTampered, characteristics: unwrapped)
            super.init(type: .temperatureSensor, characteristics: unwrapped)
        }
    }

    open class ThermostatBase: Service {
        // Required Characteristics
        public let currentHeatingCoolingState: GenericCharacteristic<Enums.CurrentHeatingCoolingState>
        public let targetHeatingCoolingState: GenericCharacteristic<Enums.TargetHeatingCoolingState>
        public let currentTemperature: GenericCharacteristic<Float>
        public let targetTemperature: GenericCharacteristic<Float>
        public let temperatureDisplayUnits: GenericCharacteristic<Enums.TemperatureDisplayUnits>

        // Optional Characteristics
        public let name: GenericCharacteristic<String>?
        public let currentRelativeHumidity: GenericCharacteristic<Float>?
        public let targetRelativeHumidity: GenericCharacteristic<Float>?
        public let coolingThresholdTemperature: GenericCharacteristic<Float>?
        public let heatingThresholdTemperature: GenericCharacteristic<Float>?

        public init(characteristics: [AnyCharacteristic] = []) {
            var unwrapped = characteristics.map { $0.wrapped }
            currentHeatingCoolingState = getOrCreateAppend(
                type: .currentHeatingCoolingState,
                characteristics: &unwrapped,
                generator: { PredefinedCharacteristic.currentHeatingCoolingState() })
            targetHeatingCoolingState = getOrCreateAppend(
                type: .targetHeatingCoolingState,
                characteristics: &unwrapped,
                generator: { PredefinedCharacteristic.targetHeatingCoolingState() })
            currentTemperature = getOrCreateAppend(
                type: .currentTemperature,
                characteristics: &unwrapped,
                generator: { PredefinedCharacteristic.currentTemperature() })
            targetTemperature = getOrCreateAppend(
                type: .targetTemperature,
                characteristics: &unwrapped,
                generator: { PredefinedCharacteristic.targetTemperature() })
            temperatureDisplayUnits = getOrCreateAppend(
                type: .temperatureDisplayUnits,
                characteristics: &unwrapped,
                generator: { PredefinedCharacteristic.temperatureDisplayUnits() })
            name = get(type: .name, characteristics: unwrapped)
            currentRelativeHumidity = get(type: .currentRelativeHumidity, characteristics: unwrapped)
            targetRelativeHumidity = get(type: .targetRelativeHumidity, characteristics: unwrapped)
            coolingThresholdTemperature = get(type: .coolingThresholdTemperature, characteristics: unwrapped)
            heatingThresholdTemperature = get(type: .heatingThresholdTemperature, characteristics: unwrapped)
            super.init(type: .thermostat, characteristics: unwrapped)
        }
    }

    open class ThreadTransportBase: Service {
        // Required Characteristics
        public let currentTransport: GenericCharacteristic<Bool>
        public let threadControlPoint: GenericCharacteristic<Data?>
        public let threadNodeCapabilities: GenericCharacteristic<UInt16>
        public let threadStatus: GenericCharacteristic<UInt16>

        // Optional Characteristics
        public let ccaEnergyDetectThreshold: GenericCharacteristic<Int>?
        public let ccaSignalDetectThreshold: GenericCharacteristic<Int>?
        public let eventRetransmissionMaximum: GenericCharacteristic<UInt8>?
        public let eventTransmissionCounters: GenericCharacteristic<UInt32>?
        public let macRetransmissionMaximum: GenericCharacteristic<UInt8>?
        public let macTransmissionCounters: GenericCharacteristic<Data>?
        public let receiverSensitivity: GenericCharacteristic<Int>?
        public let receivedSignalStrengthIndication: GenericCharacteristic<Int>?
        public let signalToNoiseRatio: GenericCharacteristic<Int>?
        public let threadOpenthreadVersion: GenericCharacteristic<String>?
        public let transmitPower: GenericCharacteristic<Int>?
        public let maximumTransmitPower: GenericCharacteristic<Int>?

        public init(characteristics: [AnyCharacteristic] = []) {
            var unwrapped = characteristics.map { $0.wrapped }
            currentTransport = getOrCreateAppend(
                type: .currentTransport,
                characteristics: &unwrapped,
                generator: { PredefinedCharacteristic.currentTransport() })
            threadControlPoint = getOrCreateAppend(
                type: .threadControlPoint,
                characteristics: &unwrapped,
                generator: { PredefinedCharacteristic.threadControlPoint() })
            threadNodeCapabilities = getOrCreateAppend(
                type: .threadNodeCapabilities,
                characteristics: &unwrapped,
                generator: { PredefinedCharacteristic.threadNodeCapabilities() })
            threadStatus = getOrCreateAppend(
                type: .threadStatus,
                characteristics: &unwrapped,
                generator: { PredefinedCharacteristic.threadStatus() })
            ccaEnergyDetectThreshold = get(type: .ccaEnergyDetectThreshold, characteristics: unwrapped)
            ccaSignalDetectThreshold = get(type: .ccaSignalDetectThreshold, characteristics: unwrapped)
            eventRetransmissionMaximum = get(type: .eventRetransmissionMaximum, characteristics: unwrapped)
            eventTransmissionCounters = get(type: .eventTransmissionCounters, characteristics: unwrapped)
            macRetransmissionMaximum = get(type: .macRetransmissionMaximum, characteristics: unwrapped)
            macTransmissionCounters = get(type: .macTransmissionCounters, characteristics: unwrapped)
            receiverSensitivity = get(type: .receiverSensitivity, characteristics: unwrapped)
            receivedSignalStrengthIndication = get(type: .receivedSignalStrengthIndication, characteristics: unwrapped)
            signalToNoiseRatio = get(type: .signalToNoiseRatio, characteristics: unwrapped)
            threadOpenthreadVersion = get(type: .threadOpenthreadVersion, characteristics: unwrapped)
            transmitPower = get(type: .transmitPower, characteristics: unwrapped)
            maximumTransmitPower = get(type: .maximumTransmitPower, characteristics: unwrapped)
            super.init(type: .threadTransport, characteristics: unwrapped)
        }
    }

    open class TransferTransportManagementBase: Service {
        // Required Characteristics
        public let supportedTransferTransportConfiguration: GenericCharacteristic<Data>
        public let setupTransferTransport: GenericCharacteristic<Data?>

        // Optional Characteristics

        public init(characteristics: [AnyCharacteristic] = []) {
            var unwrapped = characteristics.map { $0.wrapped }
            supportedTransferTransportConfiguration = getOrCreateAppend(
                type: .supportedTransferTransportConfiguration,
                characteristics: &unwrapped,
                generator: { PredefinedCharacteristic.supportedTransferTransportConfiguration() })
            setupTransferTransport = getOrCreateAppend(
                type: .setupTransferTransport,
                characteristics: &unwrapped,
                generator: { PredefinedCharacteristic.setupTransferTransport() })
            super.init(type: .transferTransportManagement, characteristics: unwrapped)
        }
    }

    open class ValveBase: Service {
        // Required Characteristics
        public let active: GenericCharacteristic<Enums.Active>
        public let inUse: GenericCharacteristic<UInt8>
        public let valveType: GenericCharacteristic<UInt8>

        // Optional Characteristics
        public let isConfigured: GenericCharacteristic<Enums.IsConfigured>?
        public let name: GenericCharacteristic<String>?
        public let remainingDuration: GenericCharacteristic<UInt32>?
        public let labelIndex: GenericCharacteristic<UInt8>?
        public let setDuration: GenericCharacteristic<UInt32>?
        public let statusFault: GenericCharacteristic<UInt8>?

        public init(characteristics: [AnyCharacteristic] = []) {
            var unwrapped = characteristics.map { $0.wrapped }
            active = getOrCreateAppend(
                type: .active,
                characteristics: &unwrapped,
                generator: { PredefinedCharacteristic.active() })
            inUse = getOrCreateAppend(
                type: .inUse,
                characteristics: &unwrapped,
                generator: { PredefinedCharacteristic.inUse() })
            valveType = getOrCreateAppend(
                type: .valveType,
                characteristics: &unwrapped,
                generator: { PredefinedCharacteristic.valveType() })
            isConfigured = get(type: .isConfigured, characteristics: unwrapped)
            name = get(type: .name, characteristics: unwrapped)
            remainingDuration = get(type: .remainingDuration, characteristics: unwrapped)
            labelIndex = get(type: .labelIndex, characteristics: unwrapped)
            setDuration = get(type: .setDuration, characteristics: unwrapped)
            statusFault = get(type: .statusFault, characteristics: unwrapped)
            super.init(type: .valve, characteristics: unwrapped)
        }
    }

    open class WiFiTransportBase: Service {
        // Required Characteristics
        public let currentTransport: GenericCharacteristic<Bool>
        public let wiFiCapabilities: GenericCharacteristic<UInt32>

        // Optional Characteristics
        public let wiFiConfigurationControl: GenericCharacteristic<Data>?

        public init(characteristics: [AnyCharacteristic] = []) {
            var unwrapped = characteristics.map { $0.wrapped }
            currentTransport = getOrCreateAppend(
                type: .currentTransport,
                characteristics: &unwrapped,
                generator: { PredefinedCharacteristic.currentTransport() })
            wiFiCapabilities = getOrCreateAppend(
                type: .wiFiCapabilities,
                characteristics: &unwrapped,
                generator: { PredefinedCharacteristic.wiFiCapabilities() })
            wiFiConfigurationControl = get(type: .wiFiConfigurationControl, characteristics: unwrapped)
            super.init(type: .wiFiTransport, characteristics: unwrapped)
        }
    }

    open class WindowBase: Service {
        // Required Characteristics
        public let currentPosition: GenericCharacteristic<UInt8>
        public let positionState: GenericCharacteristic<Enums.PositionState>
        public let targetPosition: GenericCharacteristic<UInt8>

        // Optional Characteristics
        public let name: GenericCharacteristic<String>?
        public let obstructionDetected: GenericCharacteristic<Bool>?
        public let holdPosition: GenericCharacteristic<Bool?>?

        public init(characteristics: [AnyCharacteristic] = []) {
            var unwrapped = characteristics.map { $0.wrapped }
            currentPosition = getOrCreateAppend(
                type: .currentPosition,
                characteristics: &unwrapped,
                generator: { PredefinedCharacteristic.currentPosition() })
            positionState = getOrCreateAppend(
                type: .positionState,
                characteristics: &unwrapped,
                generator: { PredefinedCharacteristic.positionState() })
            targetPosition = getOrCreateAppend(
                type: .targetPosition,
                characteristics: &unwrapped,
                generator: { PredefinedCharacteristic.targetPosition() })
            name = get(type: .name, characteristics: unwrapped)
            obstructionDetected = get(type: .obstructionDetected, characteristics: unwrapped)
            holdPosition = get(type: .holdPosition, characteristics: unwrapped)
            super.init(type: .window, characteristics: unwrapped)
        }
    }

    open class WindowCoveringBase: Service {
        // Required Characteristics
        public let currentPosition: GenericCharacteristic<UInt8>
        public let positionState: GenericCharacteristic<Enums.PositionState>
        public let targetPosition: GenericCharacteristic<UInt8>

        // Optional Characteristics
        public let currentHorizontalTiltAngle: GenericCharacteristic<Int>?
        public let targetHorizontalTiltAngle: GenericCharacteristic<Int>?
        public let name: GenericCharacteristic<String>?
        public let obstructionDetected: GenericCharacteristic<Bool>?
        public let holdPosition: GenericCharacteristic<Bool?>?
        public let currentVerticalTiltAngle: GenericCharacteristic<Int>?
        public let targetVerticalTiltAngle: GenericCharacteristic<Int>?

        public init(characteristics: [AnyCharacteristic] = []) {
            var unwrapped = characteristics.map { $0.wrapped }
            currentPosition = getOrCreateAppend(
                type: .currentPosition,
                characteristics: &unwrapped,
                generator: { PredefinedCharacteristic.currentPosition() })
            positionState = getOrCreateAppend(
                type: .positionState,
                characteristics: &unwrapped,
                generator: { PredefinedCharacteristic.positionState() })
            targetPosition = getOrCreateAppend(
                type: .targetPosition,
                characteristics: &unwrapped,
                generator: { PredefinedCharacteristic.targetPosition() })
            currentHorizontalTiltAngle = get(type: .currentHorizontalTiltAngle, characteristics: unwrapped)
            targetHorizontalTiltAngle = get(type: .targetHorizontalTiltAngle, characteristics: unwrapped)
            name = get(type: .name, characteristics: unwrapped)
            obstructionDetected = get(type: .obstructionDetected, characteristics: unwrapped)
            holdPosition = get(type: .holdPosition, characteristics: unwrapped)
            currentVerticalTiltAngle = get(type: .currentVerticalTiltAngle, characteristics: unwrapped)
            targetVerticalTiltAngle = get(type: .targetVerticalTiltAngle, characteristics: unwrapped)
            super.init(type: .windowCovering, characteristics: unwrapped)
        }
    }

}

public extension AnyCharacteristic {
    static func accessoryFlags(
        _ value: UInt32 = 0,
        permissions: [CharacteristicPermission] = [.read, .events],
        description: String? = "Accessory Flags",
        format: CharacteristicFormat? = .uint32,
        unit: CharacteristicUnit? = nil,
        maxLength: Int? = nil,
        maxValue: Double? = nil,
        minValue: Double? = nil,
        minStep: Double? = nil,
        validValues: [Double] = [],
        validValuesRange: Range<Double>? = nil
    ) -> AnyCharacteristic {
        return AnyCharacteristic(
            PredefinedCharacteristic.accessoryFlags(
            value,
            permissions: permissions,
            description: description,
            format: format,
            unit: unit,
            maxLength: maxLength,
            maxValue: maxValue,
            minValue: minValue,
            minStep: minStep,
            validValues: validValues,
            validValuesRange: validValuesRange) as Characteristic)
    }

    static func active(
        _ value: Enums.Active = .active,
        permissions: [CharacteristicPermission] = [.read, .write, .events],
        description: String? = "Active",
        format: CharacteristicFormat? = .uint8,
        unit: CharacteristicUnit? = nil,
        maxLength: Int? = nil,
        maxValue: Double? = 1,
        minValue: Double? = 0,
        minStep: Double? = 1,
        validValues: [Double] = [],
        validValuesRange: Range<Double>? = nil
    ) -> AnyCharacteristic {
        return AnyCharacteristic(
            PredefinedCharacteristic.active(
            value,
            permissions: permissions,
            description: description,
            format: format,
            unit: unit,
            maxLength: maxLength,
            maxValue: maxValue,
            minValue: minValue,
            minStep: minStep,
            validValues: validValues,
            validValuesRange: validValuesRange) as Characteristic)
    }

    static func activeIdentifier(
        _ value: UInt32 = 0,
        permissions: [CharacteristicPermission] = [.read, .write, .events],
        description: String? = "Active Identifier",
        format: CharacteristicFormat? = .uint32,
        unit: CharacteristicUnit? = nil,
        maxLength: Int? = nil,
        maxValue: Double? = nil,
        minValue: Double? = 0,
        minStep: Double? = nil,
        validValues: [Double] = [],
        validValuesRange: Range<Double>? = nil
    ) -> AnyCharacteristic {
        return AnyCharacteristic(
            PredefinedCharacteristic.activeIdentifier(
            value,
            permissions: permissions,
            description: description,
            format: format,
            unit: unit,
            maxLength: maxLength,
            maxValue: maxValue,
            minValue: minValue,
            minStep: minStep,
            validValues: validValues,
            validValuesRange: validValuesRange) as Characteristic)
    }

    static func administratorOnlyAccess(
        _ value: Bool = false,
        permissions: [CharacteristicPermission] = [.read, .write, .events],
        description: String? = "Administrator Only Access",
        format: CharacteristicFormat? = .bool,
        unit: CharacteristicUnit? = nil,
        maxLength: Int? = nil,
        maxValue: Double? = nil,
        minValue: Double? = nil,
        minStep: Double? = nil,
        validValues: [Double] = [],
        validValuesRange: Range<Double>? = nil
    ) -> AnyCharacteristic {
        return AnyCharacteristic(
            PredefinedCharacteristic.administratorOnlyAccess(
            value,
            permissions: permissions,
            description: description,
            format: format,
            unit: unit,
            maxLength: maxLength,
            maxValue: maxValue,
            minValue: minValue,
            minStep: minStep,
            validValues: validValues,
            validValuesRange: validValuesRange) as Characteristic)
    }

    static func applicationMatchingIdentifier(
        _ value: Data = Data(),
        permissions: [CharacteristicPermission] = [.read],
        description: String? = "Application Matching Identifier",
        format: CharacteristicFormat? = .tlv8,
        unit: CharacteristicUnit? = nil,
        maxLength: Int? = nil,
        maxValue: Double? = nil,
        minValue: Double? = nil,
        minStep: Double? = nil,
        validValues: [Double] = [],
        validValuesRange: Range<Double>? = nil
    ) -> AnyCharacteristic {
        return AnyCharacteristic(
            PredefinedCharacteristic.applicationMatchingIdentifier(
            value,
            permissions: permissions,
            description: description,
            format: format,
            unit: unit,
            maxLength: maxLength,
            maxValue: maxValue,
            minValue: minValue,
            minStep: minStep,
            validValues: validValues,
            validValuesRange: validValuesRange) as Characteristic)
    }

    static func audioFeedback(
        _ value: Bool = false,
        permissions: [CharacteristicPermission] = [.read, .write, .events],
        description: String? = "Audio Feedback",
        format: CharacteristicFormat? = .bool,
        unit: CharacteristicUnit? = nil,
        maxLength: Int? = nil,
        maxValue: Double? = nil,
        minValue: Double? = nil,
        minStep: Double? = nil,
        validValues: [Double] = [],
        validValuesRange: Range<Double>? = nil
    ) -> AnyCharacteristic {
        return AnyCharacteristic(
            PredefinedCharacteristic.audioFeedback(
            value,
            permissions: permissions,
            description: description,
            format: format,
            unit: unit,
            maxLength: maxLength,
            maxValue: maxValue,
            minValue: minValue,
            minStep: minStep,
            validValues: validValues,
            validValuesRange: validValuesRange) as Characteristic)
    }

    static func batteryLevel(
        _ value: UInt8 = 0,
        permissions: [CharacteristicPermission] = [.read, .events],
        description: String? = "Battery Level",
        format: CharacteristicFormat? = .uint8,
        unit: CharacteristicUnit? = .percentage,
        maxLength: Int? = nil,
        maxValue: Double? = 100,
        minValue: Double? = 0,
        minStep: Double? = 1,
        validValues: [Double] = [],
        validValuesRange: Range<Double>? = nil
    ) -> AnyCharacteristic {
        return AnyCharacteristic(
            PredefinedCharacteristic.batteryLevel(
            value,
            permissions: permissions,
            description: description,
            format: format,
            unit: unit,
            maxLength: maxLength,
            maxValue: maxValue,
            minValue: minValue,
            minStep: minStep,
            validValues: validValues,
            validValuesRange: validValuesRange) as Characteristic)
    }

    static func brightness(
        _ value: Int = 0,
        permissions: [CharacteristicPermission] = [.read, .write, .events],
        description: String? = "Brightness",
        format: CharacteristicFormat? = .int,
        unit: CharacteristicUnit? = .percentage,
        maxLength: Int? = nil,
        maxValue: Double? = 100,
        minValue: Double? = 0,
        minStep: Double? = 1,
        validValues: [Double] = [],
        validValuesRange: Range<Double>? = nil
    ) -> AnyCharacteristic {
        return AnyCharacteristic(
            PredefinedCharacteristic.brightness(
            value,
            permissions: permissions,
            description: description,
            format: format,
            unit: unit,
            maxLength: maxLength,
            maxValue: maxValue,
            minValue: minValue,
            minStep: minStep,
            validValues: validValues,
            validValuesRange: validValuesRange) as Characteristic)
    }

    static func ccaEnergyDetectThreshold(
        _ value: Int = 0,
        permissions: [CharacteristicPermission] = [.read],
        description: String? = "CCA Energy Detect Threshold",
        format: CharacteristicFormat? = .int,
        unit: CharacteristicUnit? = nil,
        maxLength: Int? = nil,
        maxValue: Double? = nil,
        minValue: Double? = nil,
        minStep: Double? = nil,
        validValues: [Double] = [],
        validValuesRange: Range<Double>? = nil
    ) -> AnyCharacteristic {
        return AnyCharacteristic(
            PredefinedCharacteristic.ccaEnergyDetectThreshold(
            value,
            permissions: permissions,
            description: description,
            format: format,
            unit: unit,
            maxLength: maxLength,
            maxValue: maxValue,
            minValue: minValue,
            minStep: minStep,
            validValues: validValues,
            validValuesRange: validValuesRange) as Characteristic)
    }

    static func ccaSignalDetectThreshold(
        _ value: Int = 0,
        permissions: [CharacteristicPermission] = [.read],
        description: String? = "CCA Signal Detect Threshold",
        format: CharacteristicFormat? = .int,
        unit: CharacteristicUnit? = nil,
        maxLength: Int? = nil,
        maxValue: Double? = nil,
        minValue: Double? = nil,
        minStep: Double? = nil,
        validValues: [Double] = [],
        validValuesRange: Range<Double>? = nil
    ) -> AnyCharacteristic {
        return AnyCharacteristic(
            PredefinedCharacteristic.ccaSignalDetectThreshold(
            value,
            permissions: permissions,
            description: description,
            format: format,
            unit: unit,
            maxLength: maxLength,
            maxValue: maxValue,
            minValue: minValue,
            minStep: minStep,
            validValues: validValues,
            validValuesRange: validValuesRange) as Characteristic)
    }

    static func carbonDioxideDetected(
        _ value: Enums.CarbonDioxideDetected = .normal,
        permissions: [CharacteristicPermission] = [.read, .events],
        description: String? = "Carbon dioxide Detected",
        format: CharacteristicFormat? = .uint8,
        unit: CharacteristicUnit? = nil,
        maxLength: Int? = nil,
        maxValue: Double? = 1,
        minValue: Double? = 0,
        minStep: Double? = 1,
        validValues: [Double] = [],
        validValuesRange: Range<Double>? = nil
    ) -> AnyCharacteristic {
        return AnyCharacteristic(
            PredefinedCharacteristic.carbonDioxideDetected(
            value,
            permissions: permissions,
            description: description,
            format: format,
            unit: unit,
            maxLength: maxLength,
            maxValue: maxValue,
            minValue: minValue,
            minStep: minStep,
            validValues: validValues,
            validValuesRange: validValuesRange) as Characteristic)
    }

    static func carbonDioxideLevel(
        _ value: Float = 0,
        permissions: [CharacteristicPermission] = [.read, .events],
        description: String? = "Carbon dioxide Level",
        format: CharacteristicFormat? = .float,
        unit: CharacteristicUnit? = .ppm,
        maxLength: Int? = nil,
        maxValue: Double? = 100000,
        minValue: Double? = 0,
        minStep: Double? = 1,
        validValues: [Double] = [],
        validValuesRange: Range<Double>? = nil
    ) -> AnyCharacteristic {
        return AnyCharacteristic(
            PredefinedCharacteristic.carbonDioxideLevel(
            value,
            permissions: permissions,
            description: description,
            format: format,
            unit: unit,
            maxLength: maxLength,
            maxValue: maxValue,
            minValue: minValue,
            minStep: minStep,
            validValues: validValues,
            validValuesRange: validValuesRange) as Characteristic)
    }

    static func carbonDioxidePeakLevel(
        _ value: Float = 0,
        permissions: [CharacteristicPermission] = [.read, .events],
        description: String? = "Carbon dioxide Peak Level",
        format: CharacteristicFormat? = .float,
        unit: CharacteristicUnit? = .ppm,
        maxLength: Int? = nil,
        maxValue: Double? = 100000,
        minValue: Double? = 0,
        minStep: Double? = 1,
        validValues: [Double] = [],
        validValuesRange: Range<Double>? = nil
    ) -> AnyCharacteristic {
        return AnyCharacteristic(
            PredefinedCharacteristic.carbonDioxidePeakLevel(
            value,
            permissions: permissions,
            description: description,
            format: format,
            unit: unit,
            maxLength: maxLength,
            maxValue: maxValue,
            minValue: minValue,
            minStep: minStep,
            validValues: validValues,
            validValuesRange: validValuesRange) as Characteristic)
    }

    static func carbonMonoxideDetected(
        _ value: UInt8 = 0,
        permissions: [CharacteristicPermission] = [.read, .events],
        description: String? = "Carbon monoxide Detected",
        format: CharacteristicFormat? = .uint8,
        unit: CharacteristicUnit? = nil,
        maxLength: Int? = nil,
        maxValue: Double? = 1,
        minValue: Double? = 0,
        minStep: Double? = 1,
        validValues: [Double] = [],
        validValuesRange: Range<Double>? = nil
    ) -> AnyCharacteristic {
        return AnyCharacteristic(
            PredefinedCharacteristic.carbonMonoxideDetected(
            value,
            permissions: permissions,
            description: description,
            format: format,
            unit: unit,
            maxLength: maxLength,
            maxValue: maxValue,
            minValue: minValue,
            minStep: minStep,
            validValues: validValues,
            validValuesRange: validValuesRange) as Characteristic)
    }

    static func carbonMonoxideLevel(
        _ value: Float = 0,
        permissions: [CharacteristicPermission] = [.read, .events],
        description: String? = "Carbon monoxide Level",
        format: CharacteristicFormat? = .float,
        unit: CharacteristicUnit? = .ppm,
        maxLength: Int? = nil,
        maxValue: Double? = 100,
        minValue: Double? = 0,
        minStep: Double? = 1,
        validValues: [Double] = [],
        validValuesRange: Range<Double>? = nil
    ) -> AnyCharacteristic {
        return AnyCharacteristic(
            PredefinedCharacteristic.carbonMonoxideLevel(
            value,
            permissions: permissions,
            description: description,
            format: format,
            unit: unit,
            maxLength: maxLength,
            maxValue: maxValue,
            minValue: minValue,
            minStep: minStep,
            validValues: validValues,
            validValuesRange: validValuesRange) as Characteristic)
    }

    static func carbonMonoxidePeakLevel(
        _ value: Float = 0,
        permissions: [CharacteristicPermission] = [.read, .events],
        description: String? = "Carbon monoxide Peak Level",
        format: CharacteristicFormat? = .float,
        unit: CharacteristicUnit? = .ppm,
        maxLength: Int? = nil,
        maxValue: Double? = 100,
        minValue: Double? = 0,
        minStep: Double? = 1,
        validValues: [Double] = [],
        validValuesRange: Range<Double>? = nil
    ) -> AnyCharacteristic {
        return AnyCharacteristic(
            PredefinedCharacteristic.carbonMonoxidePeakLevel(
            value,
            permissions: permissions,
            description: description,
            format: format,
            unit: unit,
            maxLength: maxLength,
            maxValue: maxValue,
            minValue: minValue,
            minStep: minStep,
            validValues: validValues,
            validValuesRange: validValuesRange) as Characteristic)
    }

    static func characteristicValueActiveTransitionCount(
        _ value: UInt8 = 0,
        permissions: [CharacteristicPermission] = [.read, .events],
        description: String? = "Characteristic Value Active Transition Count",
        format: CharacteristicFormat? = .uint8,
        unit: CharacteristicUnit? = nil,
        maxLength: Int? = nil,
        maxValue: Double? = nil,
        minValue: Double? = nil,
        minStep: Double? = nil,
        validValues: [Double] = [],
        validValuesRange: Range<Double>? = nil
    ) -> AnyCharacteristic {
        return AnyCharacteristic(
            PredefinedCharacteristic.characteristicValueActiveTransitionCount(
            value,
            permissions: permissions,
            description: description,
            format: format,
            unit: unit,
            maxLength: maxLength,
            maxValue: maxValue,
            minValue: minValue,
            minStep: minStep,
            validValues: validValues,
            validValuesRange: validValuesRange) as Characteristic)
    }

    static func characteristicValueTransitionControl(
        _ value: Data = Data(),
        permissions: [CharacteristicPermission] = [.read, .write],
        description: String? = "Characteristic Value Transition Control",
        format: CharacteristicFormat? = .tlv8,
        unit: CharacteristicUnit? = nil,
        maxLength: Int? = nil,
        maxValue: Double? = nil,
        minValue: Double? = nil,
        minStep: Double? = nil,
        validValues: [Double] = [],
        validValuesRange: Range<Double>? = nil
    ) -> AnyCharacteristic {
        return AnyCharacteristic(
            PredefinedCharacteristic.characteristicValueTransitionControl(
            value,
            permissions: permissions,
            description: description,
            format: format,
            unit: unit,
            maxLength: maxLength,
            maxValue: maxValue,
            minValue: minValue,
            minStep: minStep,
            validValues: validValues,
            validValuesRange: validValuesRange) as Characteristic)
    }

    static func chargingState(
        _ value: Enums.ChargingState = .notChargeable,
        permissions: [CharacteristicPermission] = [.read, .events],
        description: String? = "Charging State",
        format: CharacteristicFormat? = .uint8,
        unit: CharacteristicUnit? = nil,
        maxLength: Int? = nil,
        maxValue: Double? = 2,
        minValue: Double? = 0,
        minStep: Double? = 1,
        validValues: [Double] = [],
        validValuesRange: Range<Double>? = nil
    ) -> AnyCharacteristic {
        return AnyCharacteristic(
            PredefinedCharacteristic.chargingState(
            value,
            permissions: permissions,
            description: description,
            format: format,
            unit: unit,
            maxLength: maxLength,
            maxValue: maxValue,
            minValue: minValue,
            minStep: minStep,
            validValues: validValues,
            validValuesRange: validValuesRange) as Characteristic)
    }

    static func closedCaptions(
        _ value: Enums.ClosedCaptions = .enabled,
        permissions: [CharacteristicPermission] = [.read, .write, .events],
        description: String? = "Closed Captions",
        format: CharacteristicFormat? = .uint8,
        unit: CharacteristicUnit? = nil,
        maxLength: Int? = nil,
        maxValue: Double? = 1,
        minValue: Double? = 0,
        minStep: Double? = 1,
        validValues: [Double] = [],
        validValuesRange: Range<Double>? = nil
    ) -> AnyCharacteristic {
        return AnyCharacteristic(
            PredefinedCharacteristic.closedCaptions(
            value,
            permissions: permissions,
            description: description,
            format: format,
            unit: unit,
            maxLength: maxLength,
            maxValue: maxValue,
            minValue: minValue,
            minStep: minStep,
            validValues: validValues,
            validValuesRange: validValuesRange) as Characteristic)
    }

    static func colorTemperature(
        _ value: Int = 140,
        permissions: [CharacteristicPermission] = [.read, .write, .events],
        description: String? = "Color Temperature",
        format: CharacteristicFormat? = .int,
        unit: CharacteristicUnit? = nil,
        maxLength: Int? = nil,
        maxValue: Double? = 500,
        minValue: Double? = 140,
        minStep: Double? = 1,
        validValues: [Double] = [],
        validValuesRange: Range<Double>? = nil
    ) -> AnyCharacteristic {
        return AnyCharacteristic(
            PredefinedCharacteristic.colorTemperature(
            value,
            permissions: permissions,
            description: description,
            format: format,
            unit: unit,
            maxLength: maxLength,
            maxValue: maxValue,
            minValue: minValue,
            minStep: minStep,
            validValues: validValues,
            validValuesRange: validValuesRange) as Characteristic)
    }

    static func configuredName(
        _ value: String = "",
        permissions: [CharacteristicPermission] = [.read, .events],
        description: String? = "Configured Name",
        format: CharacteristicFormat? = .string,
        unit: CharacteristicUnit? = nil,
        maxLength: Int? = nil,
        maxValue: Double? = nil,
        minValue: Double? = nil,
        minStep: Double? = nil,
        validValues: [Double] = [],
        validValuesRange: Range<Double>? = nil
    ) -> AnyCharacteristic {
        return AnyCharacteristic(
            PredefinedCharacteristic.configuredName(
            value,
            permissions: permissions,
            description: description,
            format: format,
            unit: unit,
            maxLength: maxLength,
            maxValue: maxValue,
            minValue: minValue,
            minStep: minStep,
            validValues: validValues,
            validValuesRange: validValuesRange) as Characteristic)
    }

    static func contactSensorState(
        _ value: Enums.ContactSensorState = .detected,
        permissions: [CharacteristicPermission] = [.read, .events],
        description: String? = "Contact Sensor State",
        format: CharacteristicFormat? = .uint8,
        unit: CharacteristicUnit? = nil,
        maxLength: Int? = nil,
        maxValue: Double? = 1,
        minValue: Double? = 0,
        minStep: Double? = 1,
        validValues: [Double] = [],
        validValuesRange: Range<Double>? = nil
    ) -> AnyCharacteristic {
        return AnyCharacteristic(
            PredefinedCharacteristic.contactSensorState(
            value,
            permissions: permissions,
            description: description,
            format: format,
            unit: unit,
            maxLength: maxLength,
            maxValue: maxValue,
            minValue: minValue,
            minStep: minStep,
            validValues: validValues,
            validValuesRange: validValuesRange) as Characteristic)
    }

    static func coolingThresholdTemperature(
        _ value: Float = 10,
        permissions: [CharacteristicPermission] = [.read, .write, .events],
        description: String? = "Cooling Threshold Temperature",
        format: CharacteristicFormat? = .float,
        unit: CharacteristicUnit? = .celsius,
        maxLength: Int? = nil,
        maxValue: Double? = 35,
        minValue: Double? = 10,
        minStep: Double? = 0.1,
        validValues: [Double] = [],
        validValuesRange: Range<Double>? = nil
    ) -> AnyCharacteristic {
        return AnyCharacteristic(
            PredefinedCharacteristic.coolingThresholdTemperature(
            value,
            permissions: permissions,
            description: description,
            format: format,
            unit: unit,
            maxLength: maxLength,
            maxValue: maxValue,
            minValue: minValue,
            minStep: minStep,
            validValues: validValues,
            validValuesRange: validValuesRange) as Characteristic)
    }

    static func currentAirPurifierState(
        _ value: Enums.CurrentAirPurifierState = .inactive,
        permissions: [CharacteristicPermission] = [.read, .events],
        description: String? = "Current Air Purifier State",
        format: CharacteristicFormat? = .uint8,
        unit: CharacteristicUnit? = nil,
        maxLength: Int? = nil,
        maxValue: Double? = 2,
        minValue: Double? = 0,
        minStep: Double? = 1,
        validValues: [Double] = [],
        validValuesRange: Range<Double>? = nil
    ) -> AnyCharacteristic {
        return AnyCharacteristic(
            PredefinedCharacteristic.currentAirPurifierState(
            value,
            permissions: permissions,
            description: description,
            format: format,
            unit: unit,
            maxLength: maxLength,
            maxValue: maxValue,
            minValue: minValue,
            minStep: minStep,
            validValues: validValues,
            validValuesRange: validValuesRange) as Characteristic)
    }

    static func currentAirQuality(
        _ value: Enums.CurrentAirQuality = .good,
        permissions: [CharacteristicPermission] = [.read, .events],
        description: String? = "Current Air Quality",
        format: CharacteristicFormat? = .uint8,
        unit: CharacteristicUnit? = nil,
        maxLength: Int? = nil,
        maxValue: Double? = 5,
        minValue: Double? = 0,
        minStep: Double? = 1,
        validValues: [Double] = [],
        validValuesRange: Range<Double>? = nil
    ) -> AnyCharacteristic {
        return AnyCharacteristic(
            PredefinedCharacteristic.currentAirQuality(
            value,
            permissions: permissions,
            description: description,
            format: format,
            unit: unit,
            maxLength: maxLength,
            maxValue: maxValue,
            minValue: minValue,
            minStep: minStep,
            validValues: validValues,
            validValuesRange: validValuesRange) as Characteristic)
    }

    static func currentDoorState(
        _ value: Enums.CurrentDoorState = .open,
        permissions: [CharacteristicPermission] = [.read, .events],
        description: String? = "Current Door State",
        format: CharacteristicFormat? = .uint8,
        unit: CharacteristicUnit? = nil,
        maxLength: Int? = nil,
        maxValue: Double? = 4,
        minValue: Double? = 0,
        minStep: Double? = 1,
        validValues: [Double] = [],
        validValuesRange: Range<Double>? = nil
    ) -> AnyCharacteristic {
        return AnyCharacteristic(
            PredefinedCharacteristic.currentDoorState(
            value,
            permissions: permissions,
            description: description,
            format: format,
            unit: unit,
            maxLength: maxLength,
            maxValue: maxValue,
            minValue: minValue,
            minStep: minStep,
            validValues: validValues,
            validValuesRange: validValuesRange) as Characteristic)
    }

    static func currentFanState(
        _ value: Enums.CurrentFanState = .inactive,
        permissions: [CharacteristicPermission] = [.read, .events],
        description: String? = "Current Fan State",
        format: CharacteristicFormat? = .uint8,
        unit: CharacteristicUnit? = nil,
        maxLength: Int? = nil,
        maxValue: Double? = 2,
        minValue: Double? = 0,
        minStep: Double? = 1,
        validValues: [Double] = [],
        validValuesRange: Range<Double>? = nil
    ) -> AnyCharacteristic {
        return AnyCharacteristic(
            PredefinedCharacteristic.currentFanState(
            value,
            permissions: permissions,
            description: description,
            format: format,
            unit: unit,
            maxLength: maxLength,
            maxValue: maxValue,
            minValue: minValue,
            minStep: minStep,
            validValues: validValues,
            validValuesRange: validValuesRange) as Characteristic)
    }

    static func currentHeaterCoolerState(
        _ value: Enums.CurrentHeaterCoolerState = .heating,
        permissions: [CharacteristicPermission] = [.read, .events],
        description: String? = "Current Heater-Cooler State",
        format: CharacteristicFormat? = .uint8,
        unit: CharacteristicUnit? = nil,
        maxLength: Int? = nil,
        maxValue: Double? = 3,
        minValue: Double? = 0,
        minStep: Double? = 1,
        validValues: [Double] = [],
        validValuesRange: Range<Double>? = nil
    ) -> AnyCharacteristic {
        return AnyCharacteristic(
            PredefinedCharacteristic.currentHeaterCoolerState(
            value,
            permissions: permissions,
            description: description,
            format: format,
            unit: unit,
            maxLength: maxLength,
            maxValue: maxValue,
            minValue: minValue,
            minStep: minStep,
            validValues: validValues,
            validValuesRange: validValuesRange) as Characteristic)
    }

    static func currentHeatingCoolingState(
        _ value: Enums.CurrentHeatingCoolingState = .cool,
        permissions: [CharacteristicPermission] = [.read, .events],
        description: String? = "Current Heating Cooling State",
        format: CharacteristicFormat? = .uint8,
        unit: CharacteristicUnit? = nil,
        maxLength: Int? = nil,
        maxValue: Double? = 2,
        minValue: Double? = 0,
        minStep: Double? = 1,
        validValues: [Double] = [],
        validValuesRange: Range<Double>? = nil
    ) -> AnyCharacteristic {
        return AnyCharacteristic(
            PredefinedCharacteristic.currentHeatingCoolingState(
            value,
            permissions: permissions,
            description: description,
            format: format,
            unit: unit,
            maxLength: maxLength,
            maxValue: maxValue,
            minValue: minValue,
            minStep: minStep,
            validValues: validValues,
            validValuesRange: validValuesRange) as Characteristic)
    }

    static func currentHorizontalTiltAngle(
        _ value: Int = -90,
        permissions: [CharacteristicPermission] = [.read, .events],
        description: String? = "Current Horizontal Tilt Angle",
        format: CharacteristicFormat? = .int,
        unit: CharacteristicUnit? = .arcdegrees,
        maxLength: Int? = nil,
        maxValue: Double? = 90,
        minValue: Double? = -90,
        minStep: Double? = 1,
        validValues: [Double] = [],
        validValuesRange: Range<Double>? = nil
    ) -> AnyCharacteristic {
        return AnyCharacteristic(
            PredefinedCharacteristic.currentHorizontalTiltAngle(
            value,
            permissions: permissions,
            description: description,
            format: format,
            unit: unit,
            maxLength: maxLength,
            maxValue: maxValue,
            minValue: minValue,
            minStep: minStep,
            validValues: validValues,
            validValuesRange: validValuesRange) as Characteristic)
    }

    static func currentHumidifierDehumidifierState(
        _ value: Enums.CurrentHumidifierDehumidifierState = .inactive,
        permissions: [CharacteristicPermission] = [.read, .events],
        description: String? = "Current Humidifier-Dehumidifier State",
        format: CharacteristicFormat? = .uint8,
        unit: CharacteristicUnit? = nil,
        maxLength: Int? = nil,
        maxValue: Double? = 3,
        minValue: Double? = 0,
        minStep: Double? = 1,
        validValues: [Double] = [],
        validValuesRange: Range<Double>? = nil
    ) -> AnyCharacteristic {
        return AnyCharacteristic(
            PredefinedCharacteristic.currentHumidifierDehumidifierState(
            value,
            permissions: permissions,
            description: description,
            format: format,
            unit: unit,
            maxLength: maxLength,
            maxValue: maxValue,
            minValue: minValue,
            minStep: minStep,
            validValues: validValues,
            validValuesRange: validValuesRange) as Characteristic)
    }

    static func currentLightLevel(
        _ value: Float = 0.0001,
        permissions: [CharacteristicPermission] = [.read, .events],
        description: String? = "Current Light Level",
        format: CharacteristicFormat? = .float,
        unit: CharacteristicUnit? = .lux,
        maxLength: Int? = nil,
        maxValue: Double? = 100000,
        minValue: Double? = 0.0001,
        minStep: Double? = nil,
        validValues: [Double] = [],
        validValuesRange: Range<Double>? = nil
    ) -> AnyCharacteristic {
        return AnyCharacteristic(
            PredefinedCharacteristic.currentLightLevel(
            value,
            permissions: permissions,
            description: description,
            format: format,
            unit: unit,
            maxLength: maxLength,
            maxValue: maxValue,
            minValue: minValue,
            minStep: minStep,
            validValues: validValues,
            validValuesRange: validValuesRange) as Characteristic)
    }

    static func currentMediaState(
        _ value: UInt8 = 0,
        permissions: [CharacteristicPermission] = [.read, .events],
        description: String? = "Current Media State",
        format: CharacteristicFormat? = .uint8,
        unit: CharacteristicUnit? = nil,
        maxLength: Int? = nil,
        maxValue: Double? = 5,
        minValue: Double? = 0,
        minStep: Double? = 1,
        validValues: [Double] = [],
        validValuesRange: Range<Double>? = nil
    ) -> AnyCharacteristic {
        return AnyCharacteristic(
            PredefinedCharacteristic.currentMediaState(
            value,
            permissions: permissions,
            description: description,
            format: format,
            unit: unit,
            maxLength: maxLength,
            maxValue: maxValue,
            minValue: minValue,
            minStep: minStep,
            validValues: validValues,
            validValuesRange: validValuesRange) as Characteristic)
    }

    static func currentPosition(
        _ value: UInt8 = 0,
        permissions: [CharacteristicPermission] = [.read, .events],
        description: String? = "Current Position",
        format: CharacteristicFormat? = .uint8,
        unit: CharacteristicUnit? = .percentage,
        maxLength: Int? = nil,
        maxValue: Double? = 100,
        minValue: Double? = 0,
        minStep: Double? = 1,
        validValues: [Double] = [],
        validValuesRange: Range<Double>? = nil
    ) -> AnyCharacteristic {
        return AnyCharacteristic(
            PredefinedCharacteristic.currentPosition(
            value,
            permissions: permissions,
            description: description,
            format: format,
            unit: unit,
            maxLength: maxLength,
            maxValue: maxValue,
            minValue: minValue,
            minStep: minStep,
            validValues: validValues,
            validValuesRange: validValuesRange) as Characteristic)
    }

    static func currentRelativeHumidity(
        _ value: Float = 0,
        permissions: [CharacteristicPermission] = [.read, .events],
        description: String? = "Current Relative Humidity",
        format: CharacteristicFormat? = .float,
        unit: CharacteristicUnit? = .percentage,
        maxLength: Int? = nil,
        maxValue: Double? = 100,
        minValue: Double? = 0,
        minStep: Double? = 1,
        validValues: [Double] = [],
        validValuesRange: Range<Double>? = nil
    ) -> AnyCharacteristic {
        return AnyCharacteristic(
            PredefinedCharacteristic.currentRelativeHumidity(
            value,
            permissions: permissions,
            description: description,
            format: format,
            unit: unit,
            maxLength: maxLength,
            maxValue: maxValue,
            minValue: minValue,
            minStep: minStep,
            validValues: validValues,
            validValuesRange: validValuesRange) as Characteristic)
    }

    static func currentSlatState(
        _ value: Enums.CurrentSlatState = .inactive,
        permissions: [CharacteristicPermission] = [.read, .events],
        description: String? = "Current Slat State",
        format: CharacteristicFormat? = .uint8,
        unit: CharacteristicUnit? = nil,
        maxLength: Int? = nil,
        maxValue: Double? = 3,
        minValue: Double? = 0,
        minStep: Double? = 1,
        validValues: [Double] = [],
        validValuesRange: Range<Double>? = nil
    ) -> AnyCharacteristic {
        return AnyCharacteristic(
            PredefinedCharacteristic.currentSlatState(
            value,
            permissions: permissions,
            description: description,
            format: format,
            unit: unit,
            maxLength: maxLength,
            maxValue: maxValue,
            minValue: minValue,
            minStep: minStep,
            validValues: validValues,
            validValuesRange: validValuesRange) as Characteristic)
    }

    static func currentTemperature(
        _ value: Float = 0,
        permissions: [CharacteristicPermission] = [.read, .events],
        description: String? = "Current Temperature",
        format: CharacteristicFormat? = .float,
        unit: CharacteristicUnit? = .celsius,
        maxLength: Int? = nil,
        maxValue: Double? = 100,
        minValue: Double? = 0,
        minStep: Double? = 0.1,
        validValues: [Double] = [],
        validValuesRange: Range<Double>? = nil
    ) -> AnyCharacteristic {
        return AnyCharacteristic(
            PredefinedCharacteristic.currentTemperature(
            value,
            permissions: permissions,
            description: description,
            format: format,
            unit: unit,
            maxLength: maxLength,
            maxValue: maxValue,
            minValue: minValue,
            minStep: minStep,
            validValues: validValues,
            validValuesRange: validValuesRange) as Characteristic)
    }

    static func currentTiltAngle(
        _ value: Int = -90,
        permissions: [CharacteristicPermission] = [.read, .events],
        description: String? = "Current Tilt Angle",
        format: CharacteristicFormat? = .int,
        unit: CharacteristicUnit? = .arcdegrees,
        maxLength: Int? = nil,
        maxValue: Double? = 90,
        minValue: Double? = -90,
        minStep: Double? = 1,
        validValues: [Double] = [],
        validValuesRange: Range<Double>? = nil
    ) -> AnyCharacteristic {
        return AnyCharacteristic(
            PredefinedCharacteristic.currentTiltAngle(
            value,
            permissions: permissions,
            description: description,
            format: format,
            unit: unit,
            maxLength: maxLength,
            maxValue: maxValue,
            minValue: minValue,
            minStep: minStep,
            validValues: validValues,
            validValuesRange: validValuesRange) as Characteristic)
    }

    static func currentTransport(
        _ value: Bool = false,
        permissions: [CharacteristicPermission] = [.read],
        description: String? = "Current Transport",
        format: CharacteristicFormat? = .bool,
        unit: CharacteristicUnit? = nil,
        maxLength: Int? = nil,
        maxValue: Double? = nil,
        minValue: Double? = nil,
        minStep: Double? = nil,
        validValues: [Double] = [],
        validValuesRange: Range<Double>? = nil
    ) -> AnyCharacteristic {
        return AnyCharacteristic(
            PredefinedCharacteristic.currentTransport(
            value,
            permissions: permissions,
            description: description,
            format: format,
            unit: unit,
            maxLength: maxLength,
            maxValue: maxValue,
            minValue: minValue,
            minStep: minStep,
            validValues: validValues,
            validValuesRange: validValuesRange) as Characteristic)
    }

    static func currentVerticalTiltAngle(
        _ value: Int = -90,
        permissions: [CharacteristicPermission] = [.read, .events],
        description: String? = "Current Vertical Tilt Angle",
        format: CharacteristicFormat? = .int,
        unit: CharacteristicUnit? = .arcdegrees,
        maxLength: Int? = nil,
        maxValue: Double? = 90,
        minValue: Double? = -90,
        minStep: Double? = 1,
        validValues: [Double] = [],
        validValuesRange: Range<Double>? = nil
    ) -> AnyCharacteristic {
        return AnyCharacteristic(
            PredefinedCharacteristic.currentVerticalTiltAngle(
            value,
            permissions: permissions,
            description: description,
            format: format,
            unit: unit,
            maxLength: maxLength,
            maxValue: maxValue,
            minValue: minValue,
            minStep: minStep,
            validValues: validValues,
            validValuesRange: validValuesRange) as Characteristic)
    }

    static func currentVisibilityState(
        _ value: Enums.CurrentVisibilityState = .shown,
        permissions: [CharacteristicPermission] = [.read, .events],
        description: String? = "Current Visibility State",
        format: CharacteristicFormat? = .uint8,
        unit: CharacteristicUnit? = nil,
        maxLength: Int? = nil,
        maxValue: Double? = 3,
        minValue: Double? = 0,
        minStep: Double? = 1,
        validValues: [Double] = [],
        validValuesRange: Range<Double>? = nil
    ) -> AnyCharacteristic {
        return AnyCharacteristic(
            PredefinedCharacteristic.currentVisibilityState(
            value,
            permissions: permissions,
            description: description,
            format: format,
            unit: unit,
            maxLength: maxLength,
            maxValue: maxValue,
            minValue: minValue,
            minStep: minStep,
            validValues: validValues,
            validValuesRange: validValuesRange) as Characteristic)
    }

    static func currentWaterLevel(
        _ value: Float = 0,
        permissions: [CharacteristicPermission] = [.read, .events],
        description: String? = "Current Water Level",
        format: CharacteristicFormat? = .float,
        unit: CharacteristicUnit? = .percentage,
        maxLength: Int? = nil,
        maxValue: Double? = 100,
        minValue: Double? = 0,
        minStep: Double? = 1,
        validValues: [Double] = [],
        validValuesRange: Range<Double>? = nil
    ) -> AnyCharacteristic {
        return AnyCharacteristic(
            PredefinedCharacteristic.currentWaterLevel(
            value,
            permissions: permissions,
            description: description,
            format: format,
            unit: unit,
            maxLength: maxLength,
            maxValue: maxValue,
            minValue: minValue,
            minStep: minStep,
            validValues: validValues,
            validValuesRange: validValuesRange) as Characteristic)
    }

    static func displayOrder(
        _ value: Data = Data(),
        permissions: [CharacteristicPermission] = [.read, .events],
        description: String? = "Display Order",
        format: CharacteristicFormat? = .tlv8,
        unit: CharacteristicUnit? = nil,
        maxLength: Int? = nil,
        maxValue: Double? = nil,
        minValue: Double? = nil,
        minStep: Double? = nil,
        validValues: [Double] = [],
        validValuesRange: Range<Double>? = nil
    ) -> AnyCharacteristic {
        return AnyCharacteristic(
            PredefinedCharacteristic.displayOrder(
            value,
            permissions: permissions,
            description: description,
            format: format,
            unit: unit,
            maxLength: maxLength,
            maxValue: maxValue,
            minValue: minValue,
            minStep: minStep,
            validValues: validValues,
            validValuesRange: validValuesRange) as Characteristic)
    }

    static func eventRetransmissionMaximum(
        _ value: UInt8 = 0,
        permissions: [CharacteristicPermission] = [.read],
        description: String? = "Event Retransmission Maximum",
        format: CharacteristicFormat? = .uint8,
        unit: CharacteristicUnit? = nil,
        maxLength: Int? = nil,
        maxValue: Double? = nil,
        minValue: Double? = nil,
        minStep: Double? = nil,
        validValues: [Double] = [],
        validValuesRange: Range<Double>? = nil
    ) -> AnyCharacteristic {
        return AnyCharacteristic(
            PredefinedCharacteristic.eventRetransmissionMaximum(
            value,
            permissions: permissions,
            description: description,
            format: format,
            unit: unit,
            maxLength: maxLength,
            maxValue: maxValue,
            minValue: minValue,
            minStep: minStep,
            validValues: validValues,
            validValuesRange: validValuesRange) as Characteristic)
    }

    static func eventTransmissionCounters(
        _ value: UInt32 = 0,
        permissions: [CharacteristicPermission] = [.read],
        description: String? = "Event Transmission Counters",
        format: CharacteristicFormat? = .uint32,
        unit: CharacteristicUnit? = nil,
        maxLength: Int? = nil,
        maxValue: Double? = nil,
        minValue: Double? = nil,
        minStep: Double? = nil,
        validValues: [Double] = [],
        validValuesRange: Range<Double>? = nil
    ) -> AnyCharacteristic {
        return AnyCharacteristic(
            PredefinedCharacteristic.eventTransmissionCounters(
            value,
            permissions: permissions,
            description: description,
            format: format,
            unit: unit,
            maxLength: maxLength,
            maxValue: maxValue,
            minValue: minValue,
            minStep: minStep,
            validValues: validValues,
            validValuesRange: validValuesRange) as Characteristic)
    }

    static func filterChangeIndication(
        _ value: Enums.FilterChangeIndication = .noChange,
        permissions: [CharacteristicPermission] = [.read, .events],
        description: String? = "Filter Change indication",
        format: CharacteristicFormat? = .uint8,
        unit: CharacteristicUnit? = nil,
        maxLength: Int? = nil,
        maxValue: Double? = 1,
        minValue: Double? = 0,
        minStep: Double? = 1,
        validValues: [Double] = [],
        validValuesRange: Range<Double>? = nil
    ) -> AnyCharacteristic {
        return AnyCharacteristic(
            PredefinedCharacteristic.filterChangeIndication(
            value,
            permissions: permissions,
            description: description,
            format: format,
            unit: unit,
            maxLength: maxLength,
            maxValue: maxValue,
            minValue: minValue,
            minStep: minStep,
            validValues: validValues,
            validValuesRange: validValuesRange) as Characteristic)
    }

    static func filterLifeLevel(
        _ value: Float = 0,
        permissions: [CharacteristicPermission] = [.read, .events],
        description: String? = "Filter Life Level",
        format: CharacteristicFormat? = .float,
        unit: CharacteristicUnit? = nil,
        maxLength: Int? = nil,
        maxValue: Double? = 100,
        minValue: Double? = 0,
        minStep: Double? = 1,
        validValues: [Double] = [],
        validValuesRange: Range<Double>? = nil
    ) -> AnyCharacteristic {
        return AnyCharacteristic(
            PredefinedCharacteristic.filterLifeLevel(
            value,
            permissions: permissions,
            description: description,
            format: format,
            unit: unit,
            maxLength: maxLength,
            maxValue: maxValue,
            minValue: minValue,
            minStep: minStep,
            validValues: validValues,
            validValuesRange: validValuesRange) as Characteristic)
    }

    static func filterResetChangeIndication(
        _ value: UInt8? = nil,
        permissions: [CharacteristicPermission] = [.write],
        description: String? = "Filter Reset Change Indication",
        format: CharacteristicFormat? = .uint8,
        unit: CharacteristicUnit? = nil,
        maxLength: Int? = nil,
        maxValue: Double? = 1,
        minValue: Double? = 1,
        minStep: Double? = 1,
        validValues: [Double] = [],
        validValuesRange: Range<Double>? = nil
    ) -> AnyCharacteristic {
        return AnyCharacteristic(
            PredefinedCharacteristic.filterResetChangeIndication(
            value,
            permissions: permissions,
            description: description,
            format: format,
            unit: unit,
            maxLength: maxLength,
            maxValue: maxValue,
            minValue: minValue,
            minStep: minStep,
            validValues: validValues,
            validValuesRange: validValuesRange) as Characteristic)
    }

    static func firmwareRevision(
        _ value: String = "",
        permissions: [CharacteristicPermission] = [.read],
        description: String? = "Firmware Revision",
        format: CharacteristicFormat? = .string,
        unit: CharacteristicUnit? = nil,
        maxLength: Int? = nil,
        maxValue: Double? = nil,
        minValue: Double? = nil,
        minStep: Double? = nil,
        validValues: [Double] = [],
        validValuesRange: Range<Double>? = nil
    ) -> AnyCharacteristic {
        return AnyCharacteristic(
            PredefinedCharacteristic.firmwareRevision(
            value,
            permissions: permissions,
            description: description,
            format: format,
            unit: unit,
            maxLength: maxLength,
            maxValue: maxValue,
            minValue: minValue,
            minStep: minStep,
            validValues: validValues,
            validValuesRange: validValuesRange) as Characteristic)
    }

    static func hardwareRevision(
        _ value: String = "",
        permissions: [CharacteristicPermission] = [.read],
        description: String? = "Hardware Revision",
        format: CharacteristicFormat? = .string,
        unit: CharacteristicUnit? = nil,
        maxLength: Int? = nil,
        maxValue: Double? = nil,
        minValue: Double? = nil,
        minStep: Double? = nil,
        validValues: [Double] = [],
        validValuesRange: Range<Double>? = nil
    ) -> AnyCharacteristic {
        return AnyCharacteristic(
            PredefinedCharacteristic.hardwareRevision(
            value,
            permissions: permissions,
            description: description,
            format: format,
            unit: unit,
            maxLength: maxLength,
            maxValue: maxValue,
            minValue: minValue,
            minStep: minStep,
            validValues: validValues,
            validValuesRange: validValuesRange) as Characteristic)
    }

    static func heartBeat(
        _ value: UInt32 = 0,
        permissions: [CharacteristicPermission] = [.read, .events],
        description: String? = "Heart Beat",
        format: CharacteristicFormat? = .uint32,
        unit: CharacteristicUnit? = nil,
        maxLength: Int? = nil,
        maxValue: Double? = nil,
        minValue: Double? = nil,
        minStep: Double? = nil,
        validValues: [Double] = [],
        validValuesRange: Range<Double>? = nil
    ) -> AnyCharacteristic {
        return AnyCharacteristic(
            PredefinedCharacteristic.heartBeat(
            value,
            permissions: permissions,
            description: description,
            format: format,
            unit: unit,
            maxLength: maxLength,
            maxValue: maxValue,
            minValue: minValue,
            minStep: minStep,
            validValues: validValues,
            validValuesRange: validValuesRange) as Characteristic)
    }

    static func heatingThresholdTemperature(
        _ value: Float = 0,
        permissions: [CharacteristicPermission] = [.read, .write, .events],
        description: String? = "Heating Threshold Temperature",
        format: CharacteristicFormat? = .float,
        unit: CharacteristicUnit? = .celsius,
        maxLength: Int? = nil,
        maxValue: Double? = 25,
        minValue: Double? = 0,
        minStep: Double? = 0.1,
        validValues: [Double] = [],
        validValuesRange: Range<Double>? = nil
    ) -> AnyCharacteristic {
        return AnyCharacteristic(
            PredefinedCharacteristic.heatingThresholdTemperature(
            value,
            permissions: permissions,
            description: description,
            format: format,
            unit: unit,
            maxLength: maxLength,
            maxValue: maxValue,
            minValue: minValue,
            minStep: minStep,
            validValues: validValues,
            validValuesRange: validValuesRange) as Characteristic)
    }

    static func holdPosition(
        _ value: Bool? = nil,
        permissions: [CharacteristicPermission] = [.write],
        description: String? = "Hold Position",
        format: CharacteristicFormat? = .bool,
        unit: CharacteristicUnit? = nil,
        maxLength: Int? = nil,
        maxValue: Double? = nil,
        minValue: Double? = nil,
        minStep: Double? = nil,
        validValues: [Double] = [],
        validValuesRange: Range<Double>? = nil
    ) -> AnyCharacteristic {
        return AnyCharacteristic(
            PredefinedCharacteristic.holdPosition(
            value,
            permissions: permissions,
            description: description,
            format: format,
            unit: unit,
            maxLength: maxLength,
            maxValue: maxValue,
            minValue: minValue,
            minStep: minStep,
            validValues: validValues,
            validValuesRange: validValuesRange) as Characteristic)
    }

    static func hue(
        _ value: Float = 0,
        permissions: [CharacteristicPermission] = [.read, .write, .events],
        description: String? = "Hue",
        format: CharacteristicFormat? = .float,
        unit: CharacteristicUnit? = .arcdegrees,
        maxLength: Int? = nil,
        maxValue: Double? = 360,
        minValue: Double? = 0,
        minStep: Double? = 1,
        validValues: [Double] = [],
        validValuesRange: Range<Double>? = nil
    ) -> AnyCharacteristic {
        return AnyCharacteristic(
            PredefinedCharacteristic.hue(
            value,
            permissions: permissions,
            description: description,
            format: format,
            unit: unit,
            maxLength: maxLength,
            maxValue: maxValue,
            minValue: minValue,
            minStep: minStep,
            validValues: validValues,
            validValuesRange: validValuesRange) as Characteristic)
    }

    static func identifier(
        _ value: UInt32 = 0,
        permissions: [CharacteristicPermission] = [.read],
        description: String? = "Identifier",
        format: CharacteristicFormat? = .uint32,
        unit: CharacteristicUnit? = nil,
        maxLength: Int? = nil,
        maxValue: Double? = nil,
        minValue: Double? = 0,
        minStep: Double? = nil,
        validValues: [Double] = [],
        validValuesRange: Range<Double>? = nil
    ) -> AnyCharacteristic {
        return AnyCharacteristic(
            PredefinedCharacteristic.identifier(
            value,
            permissions: permissions,
            description: description,
            format: format,
            unit: unit,
            maxLength: maxLength,
            maxValue: maxValue,
            minValue: minValue,
            minStep: minStep,
            validValues: validValues,
            validValuesRange: validValuesRange) as Characteristic)
    }

    static func identify(
        _ value: Bool? = nil,
        permissions: [CharacteristicPermission] = [.write],
        description: String? = "Identify",
        format: CharacteristicFormat? = .bool,
        unit: CharacteristicUnit? = nil,
        maxLength: Int? = nil,
        maxValue: Double? = nil,
        minValue: Double? = nil,
        minStep: Double? = nil,
        validValues: [Double] = [],
        validValuesRange: Range<Double>? = nil
    ) -> AnyCharacteristic {
        return AnyCharacteristic(
            PredefinedCharacteristic.identify(
            value,
            permissions: permissions,
            description: description,
            format: format,
            unit: unit,
            maxLength: maxLength,
            maxValue: maxValue,
            minValue: minValue,
            minStep: minStep,
            validValues: validValues,
            validValuesRange: validValuesRange) as Characteristic)
    }

    static func inUse(
        _ value: UInt8 = 0,
        permissions: [CharacteristicPermission] = [.read, .events],
        description: String? = "In Use",
        format: CharacteristicFormat? = .uint8,
        unit: CharacteristicUnit? = nil,
        maxLength: Int? = nil,
        maxValue: Double? = 1,
        minValue: Double? = 0,
        minStep: Double? = 1,
        validValues: [Double] = [],
        validValuesRange: Range<Double>? = nil
    ) -> AnyCharacteristic {
        return AnyCharacteristic(
            PredefinedCharacteristic.inUse(
            value,
            permissions: permissions,
            description: description,
            format: format,
            unit: unit,
            maxLength: maxLength,
            maxValue: maxValue,
            minValue: minValue,
            minStep: minStep,
            validValues: validValues,
            validValuesRange: validValuesRange) as Characteristic)
    }

    static func inputDeviceType(
        _ value: Enums.InputDeviceType = .audiosystem,
        permissions: [CharacteristicPermission] = [.read, .events],
        description: String? = "Input Device Type",
        format: CharacteristicFormat? = .uint8,
        unit: CharacteristicUnit? = nil,
        maxLength: Int? = nil,
        maxValue: Double? = 6,
        minValue: Double? = 0,
        minStep: Double? = 1,
        validValues: [Double] = [],
        validValuesRange: Range<Double>? = nil
    ) -> AnyCharacteristic {
        return AnyCharacteristic(
            PredefinedCharacteristic.inputDeviceType(
            value,
            permissions: permissions,
            description: description,
            format: format,
            unit: unit,
            maxLength: maxLength,
            maxValue: maxValue,
            minValue: minValue,
            minStep: minStep,
            validValues: validValues,
            validValuesRange: validValuesRange) as Characteristic)
    }

    static func inputSourceType(
        _ value: Enums.InputSourceType = .svideo,
        permissions: [CharacteristicPermission] = [.read, .events],
        description: String? = "Input Source Type",
        format: CharacteristicFormat? = .uint8,
        unit: CharacteristicUnit? = nil,
        maxLength: Int? = nil,
        maxValue: Double? = 10,
        minValue: Double? = 0,
        minStep: Double? = 1,
        validValues: [Double] = [],
        validValuesRange: Range<Double>? = nil
    ) -> AnyCharacteristic {
        return AnyCharacteristic(
            PredefinedCharacteristic.inputSourceType(
            value,
            permissions: permissions,
            description: description,
            format: format,
            unit: unit,
            maxLength: maxLength,
            maxValue: maxValue,
            minValue: minValue,
            minStep: minStep,
            validValues: validValues,
            validValuesRange: validValuesRange) as Characteristic)
    }

    static func isConfigured(
        _ value: Enums.IsConfigured = .notconfigured,
        permissions: [CharacteristicPermission] = [.read, .events],
        description: String? = "Is Configured",
        format: CharacteristicFormat? = .uint8,
        unit: CharacteristicUnit? = nil,
        maxLength: Int? = nil,
        maxValue: Double? = 1,
        minValue: Double? = 0,
        minStep: Double? = 1,
        validValues: [Double] = [],
        validValuesRange: Range<Double>? = nil
    ) -> AnyCharacteristic {
        return AnyCharacteristic(
            PredefinedCharacteristic.isConfigured(
            value,
            permissions: permissions,
            description: description,
            format: format,
            unit: unit,
            maxLength: maxLength,
            maxValue: maxValue,
            minValue: minValue,
            minStep: minStep,
            validValues: validValues,
            validValuesRange: validValuesRange) as Characteristic)
    }

    static func labelIndex(
        _ value: UInt8 = 1,
        permissions: [CharacteristicPermission] = [.read],
        description: String? = "Label Index",
        format: CharacteristicFormat? = .uint8,
        unit: CharacteristicUnit? = nil,
        maxLength: Int? = nil,
        maxValue: Double? = 255,
        minValue: Double? = 1,
        minStep: Double? = 1,
        validValues: [Double] = [],
        validValuesRange: Range<Double>? = nil
    ) -> AnyCharacteristic {
        return AnyCharacteristic(
            PredefinedCharacteristic.labelIndex(
            value,
            permissions: permissions,
            description: description,
            format: format,
            unit: unit,
            maxLength: maxLength,
            maxValue: maxValue,
            minValue: minValue,
            minStep: minStep,
            validValues: validValues,
            validValuesRange: validValuesRange) as Characteristic)
    }

    static func labelNamespace(
        _ value: UInt8 = 0,
        permissions: [CharacteristicPermission] = [.read],
        description: String? = "Label Namespace",
        format: CharacteristicFormat? = .uint8,
        unit: CharacteristicUnit? = nil,
        maxLength: Int? = nil,
        maxValue: Double? = 4,
        minValue: Double? = 0,
        minStep: Double? = 1,
        validValues: [Double] = [],
        validValuesRange: Range<Double>? = nil
    ) -> AnyCharacteristic {
        return AnyCharacteristic(
            PredefinedCharacteristic.labelNamespace(
            value,
            permissions: permissions,
            description: description,
            format: format,
            unit: unit,
            maxLength: maxLength,
            maxValue: maxValue,
            minValue: minValue,
            minStep: minStep,
            validValues: validValues,
            validValuesRange: validValuesRange) as Characteristic)
    }

    static func leakDetected(
        _ value: Enums.LeakDetected = .leakNotDetected,
        permissions: [CharacteristicPermission] = [.read, .events],
        description: String? = "Leak Detected",
        format: CharacteristicFormat? = .uint8,
        unit: CharacteristicUnit? = nil,
        maxLength: Int? = nil,
        maxValue: Double? = 1,
        minValue: Double? = 0,
        minStep: Double? = 1,
        validValues: [Double] = [],
        validValuesRange: Range<Double>? = nil
    ) -> AnyCharacteristic {
        return AnyCharacteristic(
            PredefinedCharacteristic.leakDetected(
            value,
            permissions: permissions,
            description: description,
            format: format,
            unit: unit,
            maxLength: maxLength,
            maxValue: maxValue,
            minValue: minValue,
            minStep: minStep,
            validValues: validValues,
            validValuesRange: validValuesRange) as Characteristic)
    }

    static func lockControlPoint(
        _ value: Data? = nil,
        permissions: [CharacteristicPermission] = [.write],
        description: String? = "Lock Control Point",
        format: CharacteristicFormat? = .tlv8,
        unit: CharacteristicUnit? = nil,
        maxLength: Int? = nil,
        maxValue: Double? = nil,
        minValue: Double? = nil,
        minStep: Double? = nil,
        validValues: [Double] = [],
        validValuesRange: Range<Double>? = nil
    ) -> AnyCharacteristic {
        return AnyCharacteristic(
            PredefinedCharacteristic.lockControlPoint(
            value,
            permissions: permissions,
            description: description,
            format: format,
            unit: unit,
            maxLength: maxLength,
            maxValue: maxValue,
            minValue: minValue,
            minStep: minStep,
            validValues: validValues,
            validValuesRange: validValuesRange) as Characteristic)
    }

    static func lockCurrentState(
        _ value: Enums.LockCurrentState = .unsecured,
        permissions: [CharacteristicPermission] = [.read, .events],
        description: String? = "Lock Current State",
        format: CharacteristicFormat? = .uint8,
        unit: CharacteristicUnit? = nil,
        maxLength: Int? = nil,
        maxValue: Double? = 3,
        minValue: Double? = 0,
        minStep: Double? = 1,
        validValues: [Double] = [],
        validValuesRange: Range<Double>? = nil
    ) -> AnyCharacteristic {
        return AnyCharacteristic(
            PredefinedCharacteristic.lockCurrentState(
            value,
            permissions: permissions,
            description: description,
            format: format,
            unit: unit,
            maxLength: maxLength,
            maxValue: maxValue,
            minValue: minValue,
            minStep: minStep,
            validValues: validValues,
            validValuesRange: validValuesRange) as Characteristic)
    }

    static func lockLastKnownAction(
        _ value: UInt8 = 0,
        permissions: [CharacteristicPermission] = [.read, .events],
        description: String? = "Lock Last Known Action",
        format: CharacteristicFormat? = .uint8,
        unit: CharacteristicUnit? = nil,
        maxLength: Int? = nil,
        maxValue: Double? = 8,
        minValue: Double? = 0,
        minStep: Double? = 1,
        validValues: [Double] = [],
        validValuesRange: Range<Double>? = nil
    ) -> AnyCharacteristic {
        return AnyCharacteristic(
            PredefinedCharacteristic.lockLastKnownAction(
            value,
            permissions: permissions,
            description: description,
            format: format,
            unit: unit,
            maxLength: maxLength,
            maxValue: maxValue,
            minValue: minValue,
            minStep: minStep,
            validValues: validValues,
            validValuesRange: validValuesRange) as Characteristic)
    }

    static func lockManagementAutoSecurityTimeout(
        _ value: UInt32 = 0,
        permissions: [CharacteristicPermission] = [.read, .write, .events],
        description: String? = "Lock Management Auto Security Timeout",
        format: CharacteristicFormat? = .uint32,
        unit: CharacteristicUnit? = .seconds,
        maxLength: Int? = nil,
        maxValue: Double? = nil,
        minValue: Double? = nil,
        minStep: Double? = nil,
        validValues: [Double] = [],
        validValuesRange: Range<Double>? = nil
    ) -> AnyCharacteristic {
        return AnyCharacteristic(
            PredefinedCharacteristic.lockManagementAutoSecurityTimeout(
            value,
            permissions: permissions,
            description: description,
            format: format,
            unit: unit,
            maxLength: maxLength,
            maxValue: maxValue,
            minValue: minValue,
            minStep: minStep,
            validValues: validValues,
            validValuesRange: validValuesRange) as Characteristic)
    }

    static func lockPhysicalControls(
        _ value: UInt8 = 0,
        permissions: [CharacteristicPermission] = [.read, .write, .events],
        description: String? = "Lock Physical Controls",
        format: CharacteristicFormat? = .uint8,
        unit: CharacteristicUnit? = nil,
        maxLength: Int? = nil,
        maxValue: Double? = 1,
        minValue: Double? = 0,
        minStep: Double? = 1,
        validValues: [Double] = [],
        validValuesRange: Range<Double>? = nil
    ) -> AnyCharacteristic {
        return AnyCharacteristic(
            PredefinedCharacteristic.lockPhysicalControls(
            value,
            permissions: permissions,
            description: description,
            format: format,
            unit: unit,
            maxLength: maxLength,
            maxValue: maxValue,
            minValue: minValue,
            minStep: minStep,
            validValues: validValues,
            validValuesRange: validValuesRange) as Characteristic)
    }

    static func lockTargetState(
        _ value: Enums.LockTargetState = .unsecured,
        permissions: [CharacteristicPermission] = [.read, .write, .events],
        description: String? = "Lock Target State",
        format: CharacteristicFormat? = .uint8,
        unit: CharacteristicUnit? = nil,
        maxLength: Int? = nil,
        maxValue: Double? = 1,
        minValue: Double? = 0,
        minStep: Double? = 1,
        validValues: [Double] = [],
        validValuesRange: Range<Double>? = nil
    ) -> AnyCharacteristic {
        return AnyCharacteristic(
            PredefinedCharacteristic.lockTargetState(
            value,
            permissions: permissions,
            description: description,
            format: format,
            unit: unit,
            maxLength: maxLength,
            maxValue: maxValue,
            minValue: minValue,
            minStep: minStep,
            validValues: validValues,
            validValuesRange: validValuesRange) as Characteristic)
    }

    static func logs(
        _ value: Data = Data(),
        permissions: [CharacteristicPermission] = [.read, .events],
        description: String? = "Logs",
        format: CharacteristicFormat? = .tlv8,
        unit: CharacteristicUnit? = nil,
        maxLength: Int? = nil,
        maxValue: Double? = nil,
        minValue: Double? = nil,
        minStep: Double? = nil,
        validValues: [Double] = [],
        validValuesRange: Range<Double>? = nil
    ) -> AnyCharacteristic {
        return AnyCharacteristic(
            PredefinedCharacteristic.logs(
            value,
            permissions: permissions,
            description: description,
            format: format,
            unit: unit,
            maxLength: maxLength,
            maxValue: maxValue,
            minValue: minValue,
            minStep: minStep,
            validValues: validValues,
            validValuesRange: validValuesRange) as Characteristic)
    }

    static func macRetransmissionMaximum(
        _ value: UInt8 = 0,
        permissions: [CharacteristicPermission] = [.read],
        description: String? = "MAC Retransmission Maximum",
        format: CharacteristicFormat? = .uint8,
        unit: CharacteristicUnit? = nil,
        maxLength: Int? = nil,
        maxValue: Double? = nil,
        minValue: Double? = nil,
        minStep: Double? = nil,
        validValues: [Double] = [],
        validValuesRange: Range<Double>? = nil
    ) -> AnyCharacteristic {
        return AnyCharacteristic(
            PredefinedCharacteristic.macRetransmissionMaximum(
            value,
            permissions: permissions,
            description: description,
            format: format,
            unit: unit,
            maxLength: maxLength,
            maxValue: maxValue,
            minValue: minValue,
            minStep: minStep,
            validValues: validValues,
            validValuesRange: validValuesRange) as Characteristic)
    }

    static func macTransmissionCounters(
        _ value: Data = Data(),
        permissions: [CharacteristicPermission] = [.read],
        description: String? = "MAC Transmission Counters",
        format: CharacteristicFormat? = .data,
        unit: CharacteristicUnit? = nil,
        maxLength: Int? = nil,
        maxValue: Double? = nil,
        minValue: Double? = nil,
        minStep: Double? = nil,
        validValues: [Double] = [],
        validValuesRange: Range<Double>? = nil
    ) -> AnyCharacteristic {
        return AnyCharacteristic(
            PredefinedCharacteristic.macTransmissionCounters(
            value,
            permissions: permissions,
            description: description,
            format: format,
            unit: unit,
            maxLength: maxLength,
            maxValue: maxValue,
            minValue: minValue,
            minStep: minStep,
            validValues: validValues,
            validValuesRange: validValuesRange) as Characteristic)
    }

    static func manufacturer(
        _ value: String = "",
        permissions: [CharacteristicPermission] = [.read],
        description: String? = "Manufacturer",
        format: CharacteristicFormat? = .string,
        unit: CharacteristicUnit? = nil,
        maxLength: Int? = nil,
        maxValue: Double? = nil,
        minValue: Double? = nil,
        minStep: Double? = nil,
        validValues: [Double] = [],
        validValuesRange: Range<Double>? = nil
    ) -> AnyCharacteristic {
        return AnyCharacteristic(
            PredefinedCharacteristic.manufacturer(
            value,
            permissions: permissions,
            description: description,
            format: format,
            unit: unit,
            maxLength: maxLength,
            maxValue: maxValue,
            minValue: minValue,
            minStep: minStep,
            validValues: validValues,
            validValuesRange: validValuesRange) as Characteristic)
    }

    static func maximumTransmitPower(
        _ value: Int = 0,
        permissions: [CharacteristicPermission] = [.read],
        description: String? = "Maximum Transmit Power",
        format: CharacteristicFormat? = .int,
        unit: CharacteristicUnit? = nil,
        maxLength: Int? = nil,
        maxValue: Double? = nil,
        minValue: Double? = nil,
        minStep: Double? = nil,
        validValues: [Double] = [],
        validValuesRange: Range<Double>? = nil
    ) -> AnyCharacteristic {
        return AnyCharacteristic(
            PredefinedCharacteristic.maximumTransmitPower(
            value,
            permissions: permissions,
            description: description,
            format: format,
            unit: unit,
            maxLength: maxLength,
            maxValue: maxValue,
            minValue: minValue,
            minStep: minStep,
            validValues: validValues,
            validValuesRange: validValuesRange) as Characteristic)
    }

    static func model(
        _ value: String = "",
        permissions: [CharacteristicPermission] = [.read],
        description: String? = "Model",
        format: CharacteristicFormat? = .string,
        unit: CharacteristicUnit? = nil,
        maxLength: Int? = nil,
        maxValue: Double? = nil,
        minValue: Double? = nil,
        minStep: Double? = nil,
        validValues: [Double] = [],
        validValuesRange: Range<Double>? = nil
    ) -> AnyCharacteristic {
        return AnyCharacteristic(
            PredefinedCharacteristic.model(
            value,
            permissions: permissions,
            description: description,
            format: format,
            unit: unit,
            maxLength: maxLength,
            maxValue: maxValue,
            minValue: minValue,
            minStep: minStep,
            validValues: validValues,
            validValuesRange: validValuesRange) as Characteristic)
    }

    static func motionDetected(
        _ value: Bool = false,
        permissions: [CharacteristicPermission] = [.read, .events],
        description: String? = "Motion Detected",
        format: CharacteristicFormat? = .bool,
        unit: CharacteristicUnit? = nil,
        maxLength: Int? = nil,
        maxValue: Double? = nil,
        minValue: Double? = nil,
        minStep: Double? = nil,
        validValues: [Double] = [],
        validValuesRange: Range<Double>? = nil
    ) -> AnyCharacteristic {
        return AnyCharacteristic(
            PredefinedCharacteristic.motionDetected(
            value,
            permissions: permissions,
            description: description,
            format: format,
            unit: unit,
            maxLength: maxLength,
            maxValue: maxValue,
            minValue: minValue,
            minStep: minStep,
            validValues: validValues,
            validValuesRange: validValuesRange) as Characteristic)
    }

    static func mute(
        _ value: Bool = false,
        permissions: [CharacteristicPermission] = [.read, .write, .events],
        description: String? = "Mute",
        format: CharacteristicFormat? = .bool,
        unit: CharacteristicUnit? = nil,
        maxLength: Int? = nil,
        maxValue: Double? = nil,
        minValue: Double? = nil,
        minStep: Double? = nil,
        validValues: [Double] = [],
        validValuesRange: Range<Double>? = nil
    ) -> AnyCharacteristic {
        return AnyCharacteristic(
            PredefinedCharacteristic.mute(
            value,
            permissions: permissions,
            description: description,
            format: format,
            unit: unit,
            maxLength: maxLength,
            maxValue: maxValue,
            minValue: minValue,
            minStep: minStep,
            validValues: validValues,
            validValuesRange: validValuesRange) as Characteristic)
    }

    static func name(
        _ value: String = "",
        permissions: [CharacteristicPermission] = [.read],
        description: String? = "Name",
        format: CharacteristicFormat? = .string,
        unit: CharacteristicUnit? = nil,
        maxLength: Int? = nil,
        maxValue: Double? = nil,
        minValue: Double? = nil,
        minStep: Double? = nil,
        validValues: [Double] = [],
        validValuesRange: Range<Double>? = nil
    ) -> AnyCharacteristic {
        return AnyCharacteristic(
            PredefinedCharacteristic.name(
            value,
            permissions: permissions,
            description: description,
            format: format,
            unit: unit,
            maxLength: maxLength,
            maxValue: maxValue,
            minValue: minValue,
            minStep: minStep,
            validValues: validValues,
            validValuesRange: validValuesRange) as Characteristic)
    }

    static func nitrogenDioxideDensity(
        _ value: Float = 0,
        permissions: [CharacteristicPermission] = [.read, .events],
        description: String? = "Nitrogen dioxide Density",
        format: CharacteristicFormat? = .float,
        unit: CharacteristicUnit? = .microgramsPerMCubed,
        maxLength: Int? = nil,
        maxValue: Double? = 1000,
        minValue: Double? = 0,
        minStep: Double? = 1,
        validValues: [Double] = [],
        validValuesRange: Range<Double>? = nil
    ) -> AnyCharacteristic {
        return AnyCharacteristic(
            PredefinedCharacteristic.nitrogenDioxideDensity(
            value,
            permissions: permissions,
            description: description,
            format: format,
            unit: unit,
            maxLength: maxLength,
            maxValue: maxValue,
            minValue: minValue,
            minStep: minStep,
            validValues: validValues,
            validValuesRange: validValuesRange) as Characteristic)
    }

    static func obstructionDetected(
        _ value: Bool = false,
        permissions: [CharacteristicPermission] = [.read, .events],
        description: String? = "Obstruction Detected",
        format: CharacteristicFormat? = .bool,
        unit: CharacteristicUnit? = nil,
        maxLength: Int? = nil,
        maxValue: Double? = nil,
        minValue: Double? = nil,
        minStep: Double? = nil,
        validValues: [Double] = [],
        validValuesRange: Range<Double>? = nil
    ) -> AnyCharacteristic {
        return AnyCharacteristic(
            PredefinedCharacteristic.obstructionDetected(
            value,
            permissions: permissions,
            description: description,
            format: format,
            unit: unit,
            maxLength: maxLength,
            maxValue: maxValue,
            minValue: minValue,
            minStep: minStep,
            validValues: validValues,
            validValuesRange: validValuesRange) as Characteristic)
    }

    static func occupancyDetected(
        _ value: Enums.OccupancyDetected = .occupancyDetected,
        permissions: [CharacteristicPermission] = [.read, .events],
        description: String? = "Occupancy Detected",
        format: CharacteristicFormat? = .uint8,
        unit: CharacteristicUnit? = nil,
        maxLength: Int? = nil,
        maxValue: Double? = 1,
        minValue: Double? = 0,
        minStep: Double? = 1,
        validValues: [Double] = [],
        validValuesRange: Range<Double>? = nil
    ) -> AnyCharacteristic {
        return AnyCharacteristic(
            PredefinedCharacteristic.occupancyDetected(
            value,
            permissions: permissions,
            description: description,
            format: format,
            unit: unit,
            maxLength: maxLength,
            maxValue: maxValue,
            minValue: minValue,
            minStep: minStep,
            validValues: validValues,
            validValuesRange: validValuesRange) as Characteristic)
    }

    static func operatingStateResponse(
        _ value: Data = Data(),
        permissions: [CharacteristicPermission] = [.read, .events],
        description: String? = "Operating State Response",
        format: CharacteristicFormat? = .tlv8,
        unit: CharacteristicUnit? = nil,
        maxLength: Int? = nil,
        maxValue: Double? = nil,
        minValue: Double? = nil,
        minStep: Double? = nil,
        validValues: [Double] = [],
        validValuesRange: Range<Double>? = nil
    ) -> AnyCharacteristic {
        return AnyCharacteristic(
            PredefinedCharacteristic.operatingStateResponse(
            value,
            permissions: permissions,
            description: description,
            format: format,
            unit: unit,
            maxLength: maxLength,
            maxValue: maxValue,
            minValue: minValue,
            minStep: minStep,
            validValues: validValues,
            validValuesRange: validValuesRange) as Characteristic)
    }

    static func outletInUse(
        _ value: Bool = false,
        permissions: [CharacteristicPermission] = [.read, .events],
        description: String? = "Outlet In Use",
        format: CharacteristicFormat? = .bool,
        unit: CharacteristicUnit? = nil,
        maxLength: Int? = nil,
        maxValue: Double? = nil,
        minValue: Double? = nil,
        minStep: Double? = nil,
        validValues: [Double] = [],
        validValuesRange: Range<Double>? = nil
    ) -> AnyCharacteristic {
        return AnyCharacteristic(
            PredefinedCharacteristic.outletInUse(
            value,
            permissions: permissions,
            description: description,
            format: format,
            unit: unit,
            maxLength: maxLength,
            maxValue: maxValue,
            minValue: minValue,
            minStep: minStep,
            validValues: validValues,
            validValuesRange: validValuesRange) as Characteristic)
    }

    static func ozoneDensity(
        _ value: Float = 0,
        permissions: [CharacteristicPermission] = [.read, .events],
        description: String? = "Ozone Density",
        format: CharacteristicFormat? = .float,
        unit: CharacteristicUnit? = .microgramsPerMCubed,
        maxLength: Int? = nil,
        maxValue: Double? = 1000,
        minValue: Double? = 0,
        minStep: Double? = 1,
        validValues: [Double] = [],
        validValuesRange: Range<Double>? = nil
    ) -> AnyCharacteristic {
        return AnyCharacteristic(
            PredefinedCharacteristic.ozoneDensity(
            value,
            permissions: permissions,
            description: description,
            format: format,
            unit: unit,
            maxLength: maxLength,
            maxValue: maxValue,
            minValue: minValue,
            minStep: minStep,
            validValues: validValues,
            validValuesRange: validValuesRange) as Characteristic)
    }

    static func pm10Density(
        _ value: Float = 0,
        permissions: [CharacteristicPermission] = [.read, .events],
        description: String? = "PM10 Density",
        format: CharacteristicFormat? = .float,
        unit: CharacteristicUnit? = .microgramsPerMCubed,
        maxLength: Int? = nil,
        maxValue: Double? = 1000,
        minValue: Double? = 0,
        minStep: Double? = 1,
        validValues: [Double] = [],
        validValuesRange: Range<Double>? = nil
    ) -> AnyCharacteristic {
        return AnyCharacteristic(
            PredefinedCharacteristic.pm10Density(
            value,
            permissions: permissions,
            description: description,
            format: format,
            unit: unit,
            maxLength: maxLength,
            maxValue: maxValue,
            minValue: minValue,
            minStep: minStep,
            validValues: validValues,
            validValuesRange: validValuesRange) as Characteristic)
    }

    static func pm2_5Density(
        _ value: Float = 0,
        permissions: [CharacteristicPermission] = [.read, .events],
        description: String? = "PM2.5 Density",
        format: CharacteristicFormat? = .float,
        unit: CharacteristicUnit? = .microgramsPerMCubed,
        maxLength: Int? = nil,
        maxValue: Double? = 1000,
        minValue: Double? = 0,
        minStep: Double? = 1,
        validValues: [Double] = [],
        validValuesRange: Range<Double>? = nil
    ) -> AnyCharacteristic {
        return AnyCharacteristic(
            PredefinedCharacteristic.pm2_5Density(
            value,
            permissions: permissions,
            description: description,
            format: format,
            unit: unit,
            maxLength: maxLength,
            maxValue: maxValue,
            minValue: minValue,
            minStep: minStep,
            validValues: validValues,
            validValuesRange: validValuesRange) as Characteristic)
    }

    static func pictureMode(
        _ value: Enums.PictureMode = .game,
        permissions: [CharacteristicPermission] = [.read, .write, .events],
        description: String? = "Picture Mode",
        format: CharacteristicFormat? = .uint8,
        unit: CharacteristicUnit? = nil,
        maxLength: Int? = nil,
        maxValue: Double? = 13,
        minValue: Double? = 0,
        minStep: Double? = 1,
        validValues: [Double] = [],
        validValuesRange: Range<Double>? = nil
    ) -> AnyCharacteristic {
        return AnyCharacteristic(
            PredefinedCharacteristic.pictureMode(
            value,
            permissions: permissions,
            description: description,
            format: format,
            unit: unit,
            maxLength: maxLength,
            maxValue: maxValue,
            minValue: minValue,
            minStep: minStep,
            validValues: validValues,
            validValuesRange: validValuesRange) as Characteristic)
    }

    static func ping(
        _ value: Data = Data(),
        permissions: [CharacteristicPermission] = [.read],
        description: String? = "Ping",
        format: CharacteristicFormat? = .data,
        unit: CharacteristicUnit? = nil,
        maxLength: Int? = nil,
        maxValue: Double? = nil,
        minValue: Double? = nil,
        minStep: Double? = nil,
        validValues: [Double] = [],
        validValuesRange: Range<Double>? = nil
    ) -> AnyCharacteristic {
        return AnyCharacteristic(
            PredefinedCharacteristic.ping(
            value,
            permissions: permissions,
            description: description,
            format: format,
            unit: unit,
            maxLength: maxLength,
            maxValue: maxValue,
            minValue: minValue,
            minStep: minStep,
            validValues: validValues,
            validValuesRange: validValuesRange) as Characteristic)
    }

    static func positionState(
        _ value: Enums.PositionState = .increasing,
        permissions: [CharacteristicPermission] = [.read, .events],
        description: String? = "Position State",
        format: CharacteristicFormat? = .uint8,
        unit: CharacteristicUnit? = nil,
        maxLength: Int? = nil,
        maxValue: Double? = 2,
        minValue: Double? = 0,
        minStep: Double? = 1,
        validValues: [Double] = [],
        validValuesRange: Range<Double>? = nil
    ) -> AnyCharacteristic {
        return AnyCharacteristic(
            PredefinedCharacteristic.positionState(
            value,
            permissions: permissions,
            description: description,
            format: format,
            unit: unit,
            maxLength: maxLength,
            maxValue: maxValue,
            minValue: minValue,
            minStep: minStep,
            validValues: validValues,
            validValuesRange: validValuesRange) as Characteristic)
    }

    static func powerModeSelection(
        _ value: Enums.PowerModeSelection? = nil,
        permissions: [CharacteristicPermission] = [.write],
        description: String? = "Power Mode Selection",
        format: CharacteristicFormat? = .uint8,
        unit: CharacteristicUnit? = nil,
        maxLength: Int? = nil,
        maxValue: Double? = 1,
        minValue: Double? = 0,
        minStep: Double? = 1,
        validValues: [Double] = [],
        validValuesRange: Range<Double>? = nil
    ) -> AnyCharacteristic {
        return AnyCharacteristic(
            PredefinedCharacteristic.powerModeSelection(
            value,
            permissions: permissions,
            description: description,
            format: format,
            unit: unit,
            maxLength: maxLength,
            maxValue: maxValue,
            minValue: minValue,
            minStep: minStep,
            validValues: validValues,
            validValuesRange: validValuesRange) as Characteristic)
    }

    static func powerState(
        _ value: Bool = false,
        permissions: [CharacteristicPermission] = [.read, .write, .events],
        description: String? = "Power State",
        format: CharacteristicFormat? = .bool,
        unit: CharacteristicUnit? = nil,
        maxLength: Int? = nil,
        maxValue: Double? = nil,
        minValue: Double? = nil,
        minStep: Double? = nil,
        validValues: [Double] = [],
        validValuesRange: Range<Double>? = nil
    ) -> AnyCharacteristic {
        return AnyCharacteristic(
            PredefinedCharacteristic.powerState(
            value,
            permissions: permissions,
            description: description,
            format: format,
            unit: unit,
            maxLength: maxLength,
            maxValue: maxValue,
            minValue: minValue,
            minStep: minStep,
            validValues: validValues,
            validValuesRange: validValuesRange) as Characteristic)
    }

    static func productData(
        _ value: Data = Data(),
        permissions: [CharacteristicPermission] = [.read],
        description: String? = "Product Data",
        format: CharacteristicFormat? = .data,
        unit: CharacteristicUnit? = nil,
        maxLength: Int? = nil,
        maxValue: Double? = nil,
        minValue: Double? = nil,
        minStep: Double? = nil,
        validValues: [Double] = [],
        validValuesRange: Range<Double>? = nil
    ) -> AnyCharacteristic {
        return AnyCharacteristic(
            PredefinedCharacteristic.productData(
            value,
            permissions: permissions,
            description: description,
            format: format,
            unit: unit,
            maxLength: maxLength,
            maxValue: maxValue,
            minValue: minValue,
            minStep: minStep,
            validValues: validValues,
            validValuesRange: validValuesRange) as Characteristic)
    }

    static func programMode(
        _ value: UInt8 = 0,
        permissions: [CharacteristicPermission] = [.read, .events],
        description: String? = "Program Mode",
        format: CharacteristicFormat? = .uint8,
        unit: CharacteristicUnit? = nil,
        maxLength: Int? = nil,
        maxValue: Double? = 2,
        minValue: Double? = 0,
        minStep: Double? = 1,
        validValues: [Double] = [],
        validValuesRange: Range<Double>? = nil
    ) -> AnyCharacteristic {
        return AnyCharacteristic(
            PredefinedCharacteristic.programMode(
            value,
            permissions: permissions,
            description: description,
            format: format,
            unit: unit,
            maxLength: maxLength,
            maxValue: maxValue,
            minValue: minValue,
            minStep: minStep,
            validValues: validValues,
            validValuesRange: validValuesRange) as Characteristic)
    }

    static func programmableSwitchEvent(
        _ value: UInt8 = 0,
        permissions: [CharacteristicPermission] = [.read, .events],
        description: String? = "Programmable Switch Event",
        format: CharacteristicFormat? = .uint8,
        unit: CharacteristicUnit? = nil,
        maxLength: Int? = nil,
        maxValue: Double? = 2,
        minValue: Double? = 0,
        minStep: Double? = 1,
        validValues: [Double] = [],
        validValuesRange: Range<Double>? = nil
    ) -> AnyCharacteristic {
        return AnyCharacteristic(
            PredefinedCharacteristic.programmableSwitchEvent(
            value,
            permissions: permissions,
            description: description,
            format: format,
            unit: unit,
            maxLength: maxLength,
            maxValue: maxValue,
            minValue: minValue,
            minStep: minStep,
            validValues: validValues,
            validValuesRange: validValuesRange) as Characteristic)
    }

    static func programmableSwitchOutputState(
        _ value: UInt8 = 0,
        permissions: [CharacteristicPermission] = [.read, .write, .events],
        description: String? = "Programmable Switch Output State",
        format: CharacteristicFormat? = .uint8,
        unit: CharacteristicUnit? = nil,
        maxLength: Int? = nil,
        maxValue: Double? = 1,
        minValue: Double? = 0,
        minStep: Double? = 1,
        validValues: [Double] = [],
        validValuesRange: Range<Double>? = nil
    ) -> AnyCharacteristic {
        return AnyCharacteristic(
            PredefinedCharacteristic.programmableSwitchOutputState(
            value,
            permissions: permissions,
            description: description,
            format: format,
            unit: unit,
            maxLength: maxLength,
            maxValue: maxValue,
            minValue: minValue,
            minStep: minStep,
            validValues: validValues,
            validValuesRange: validValuesRange) as Characteristic)
    }

    static func receivedSignalStrengthIndication(
        _ value: Int = 0,
        permissions: [CharacteristicPermission] = [.read],
        description: String? = "Received Signal Strength Indication",
        format: CharacteristicFormat? = .int,
        unit: CharacteristicUnit? = nil,
        maxLength: Int? = nil,
        maxValue: Double? = nil,
        minValue: Double? = nil,
        minStep: Double? = nil,
        validValues: [Double] = [],
        validValuesRange: Range<Double>? = nil
    ) -> AnyCharacteristic {
        return AnyCharacteristic(
            PredefinedCharacteristic.receivedSignalStrengthIndication(
            value,
            permissions: permissions,
            description: description,
            format: format,
            unit: unit,
            maxLength: maxLength,
            maxValue: maxValue,
            minValue: minValue,
            minStep: minStep,
            validValues: validValues,
            validValuesRange: validValuesRange) as Characteristic)
    }

    static func receiverSensitivity(
        _ value: Int = 0,
        permissions: [CharacteristicPermission] = [.read],
        description: String? = "Receiver Sensitivity",
        format: CharacteristicFormat? = .int,
        unit: CharacteristicUnit? = nil,
        maxLength: Int? = nil,
        maxValue: Double? = nil,
        minValue: Double? = nil,
        minStep: Double? = nil,
        validValues: [Double] = [],
        validValuesRange: Range<Double>? = nil
    ) -> AnyCharacteristic {
        return AnyCharacteristic(
            PredefinedCharacteristic.receiverSensitivity(
            value,
            permissions: permissions,
            description: description,
            format: format,
            unit: unit,
            maxLength: maxLength,
            maxValue: maxValue,
            minValue: minValue,
            minStep: minStep,
            validValues: validValues,
            validValuesRange: validValuesRange) as Characteristic)
    }

    static func relativeHumidityDehumidifierThreshold(
        _ value: Float = 0,
        permissions: [CharacteristicPermission] = [.read, .write, .events],
        description: String? = "Relative Humidity Dehumidifier Threshold",
        format: CharacteristicFormat? = .float,
        unit: CharacteristicUnit? = .percentage,
        maxLength: Int? = nil,
        maxValue: Double? = 100,
        minValue: Double? = 0,
        minStep: Double? = 1,
        validValues: [Double] = [],
        validValuesRange: Range<Double>? = nil
    ) -> AnyCharacteristic {
        return AnyCharacteristic(
            PredefinedCharacteristic.relativeHumidityDehumidifierThreshold(
            value,
            permissions: permissions,
            description: description,
            format: format,
            unit: unit,
            maxLength: maxLength,
            maxValue: maxValue,
            minValue: minValue,
            minStep: minStep,
            validValues: validValues,
            validValuesRange: validValuesRange) as Characteristic)
    }

    static func relativeHumidityHumidifierThreshold(
        _ value: Float = 0,
        permissions: [CharacteristicPermission] = [.read, .write, .events],
        description: String? = "Relative Humidity Humidifier Threshold",
        format: CharacteristicFormat? = .float,
        unit: CharacteristicUnit? = .percentage,
        maxLength: Int? = nil,
        maxValue: Double? = 100,
        minValue: Double? = 0,
        minStep: Double? = 1,
        validValues: [Double] = [],
        validValuesRange: Range<Double>? = nil
    ) -> AnyCharacteristic {
        return AnyCharacteristic(
            PredefinedCharacteristic.relativeHumidityHumidifierThreshold(
            value,
            permissions: permissions,
            description: description,
            format: format,
            unit: unit,
            maxLength: maxLength,
            maxValue: maxValue,
            minValue: minValue,
            minStep: minStep,
            validValues: validValues,
            validValuesRange: validValuesRange) as Characteristic)
    }

    static func remainingDuration(
        _ value: UInt32 = 0,
        permissions: [CharacteristicPermission] = [.read, .events],
        description: String? = "Remaining Duration",
        format: CharacteristicFormat? = .uint32,
        unit: CharacteristicUnit? = .seconds,
        maxLength: Int? = nil,
        maxValue: Double? = 3600,
        minValue: Double? = 0,
        minStep: Double? = 1,
        validValues: [Double] = [],
        validValuesRange: Range<Double>? = nil
    ) -> AnyCharacteristic {
        return AnyCharacteristic(
            PredefinedCharacteristic.remainingDuration(
            value,
            permissions: permissions,
            description: description,
            format: format,
            unit: unit,
            maxLength: maxLength,
            maxValue: maxValue,
            minValue: minValue,
            minStep: minStep,
            validValues: validValues,
            validValuesRange: validValuesRange) as Characteristic)
    }

    static func remoteKey(
        _ value: Enums.RemoteKey? = nil,
        permissions: [CharacteristicPermission] = [.write],
        description: String? = "Remote Key",
        format: CharacteristicFormat? = .uint8,
        unit: CharacteristicUnit? = nil,
        maxLength: Int? = nil,
        maxValue: Double? = 16,
        minValue: Double? = 0,
        minStep: Double? = 1,
        validValues: [Double] = [],
        validValuesRange: Range<Double>? = nil
    ) -> AnyCharacteristic {
        return AnyCharacteristic(
            PredefinedCharacteristic.remoteKey(
            value,
            permissions: permissions,
            description: description,
            format: format,
            unit: unit,
            maxLength: maxLength,
            maxValue: maxValue,
            minValue: minValue,
            minStep: minStep,
            validValues: validValues,
            validValuesRange: validValuesRange) as Characteristic)
    }

    static func rotationDirection(
        _ value: Enums.RotationDirection = .counterclockwise,
        permissions: [CharacteristicPermission] = [.read, .write, .events],
        description: String? = "Rotation Direction",
        format: CharacteristicFormat? = .int,
        unit: CharacteristicUnit? = nil,
        maxLength: Int? = nil,
        maxValue: Double? = 1,
        minValue: Double? = 0,
        minStep: Double? = 1,
        validValues: [Double] = [],
        validValuesRange: Range<Double>? = nil
    ) -> AnyCharacteristic {
        return AnyCharacteristic(
            PredefinedCharacteristic.rotationDirection(
            value,
            permissions: permissions,
            description: description,
            format: format,
            unit: unit,
            maxLength: maxLength,
            maxValue: maxValue,
            minValue: minValue,
            minStep: minStep,
            validValues: validValues,
            validValuesRange: validValuesRange) as Characteristic)
    }

    static func rotationSpeed(
        _ value: Float = 0,
        permissions: [CharacteristicPermission] = [.read, .write, .events],
        description: String? = "Rotation Speed",
        format: CharacteristicFormat? = .float,
        unit: CharacteristicUnit? = nil,
        maxLength: Int? = nil,
        maxValue: Double? = 100,
        minValue: Double? = 0,
        minStep: Double? = 1,
        validValues: [Double] = [],
        validValuesRange: Range<Double>? = nil
    ) -> AnyCharacteristic {
        return AnyCharacteristic(
            PredefinedCharacteristic.rotationSpeed(
            value,
            permissions: permissions,
            description: description,
            format: format,
            unit: unit,
            maxLength: maxLength,
            maxValue: maxValue,
            minValue: minValue,
            minStep: minStep,
            validValues: validValues,
            validValuesRange: validValuesRange) as Characteristic)
    }

    static func saturation(
        _ value: Float = 0,
        permissions: [CharacteristicPermission] = [.read, .write, .events],
        description: String? = "Saturation",
        format: CharacteristicFormat? = .float,
        unit: CharacteristicUnit? = .percentage,
        maxLength: Int? = nil,
        maxValue: Double? = 100,
        minValue: Double? = 0,
        minStep: Double? = 1,
        validValues: [Double] = [],
        validValuesRange: Range<Double>? = nil
    ) -> AnyCharacteristic {
        return AnyCharacteristic(
            PredefinedCharacteristic.saturation(
            value,
            permissions: permissions,
            description: description,
            format: format,
            unit: unit,
            maxLength: maxLength,
            maxValue: maxValue,
            minValue: minValue,
            minStep: minStep,
            validValues: validValues,
            validValuesRange: validValuesRange) as Characteristic)
    }

    static func securitySystemAlarmType(
        _ value: UInt8 = 0,
        permissions: [CharacteristicPermission] = [.read, .events],
        description: String? = "Security System Alarm Type",
        format: CharacteristicFormat? = .uint8,
        unit: CharacteristicUnit? = nil,
        maxLength: Int? = nil,
        maxValue: Double? = 1,
        minValue: Double? = 0,
        minStep: Double? = 1,
        validValues: [Double] = [],
        validValuesRange: Range<Double>? = nil
    ) -> AnyCharacteristic {
        return AnyCharacteristic(
            PredefinedCharacteristic.securitySystemAlarmType(
            value,
            permissions: permissions,
            description: description,
            format: format,
            unit: unit,
            maxLength: maxLength,
            maxValue: maxValue,
            minValue: minValue,
            minStep: minStep,
            validValues: validValues,
            validValuesRange: validValuesRange) as Characteristic)
    }

    static func securitySystemCurrentState(
        _ value: Enums.SecuritySystemCurrentState = .disarm,
        permissions: [CharacteristicPermission] = [.read, .events],
        description: String? = "Security System Current State",
        format: CharacteristicFormat? = .uint8,
        unit: CharacteristicUnit? = nil,
        maxLength: Int? = nil,
        maxValue: Double? = 4,
        minValue: Double? = 0,
        minStep: Double? = 1,
        validValues: [Double] = [],
        validValuesRange: Range<Double>? = nil
    ) -> AnyCharacteristic {
        return AnyCharacteristic(
            PredefinedCharacteristic.securitySystemCurrentState(
            value,
            permissions: permissions,
            description: description,
            format: format,
            unit: unit,
            maxLength: maxLength,
            maxValue: maxValue,
            minValue: minValue,
            minStep: minStep,
            validValues: validValues,
            validValuesRange: validValuesRange) as Characteristic)
    }

    static func securitySystemTargetState(
        _ value: Enums.SecuritySystemTargetState = .disarm,
        permissions: [CharacteristicPermission] = [.read, .write, .events],
        description: String? = "Security System Target State",
        format: CharacteristicFormat? = .uint8,
        unit: CharacteristicUnit? = nil,
        maxLength: Int? = nil,
        maxValue: Double? = 3,
        minValue: Double? = 0,
        minStep: Double? = 1,
        validValues: [Double] = [],
        validValuesRange: Range<Double>? = nil
    ) -> AnyCharacteristic {
        return AnyCharacteristic(
            PredefinedCharacteristic.securitySystemTargetState(
            value,
            permissions: permissions,
            description: description,
            format: format,
            unit: unit,
            maxLength: maxLength,
            maxValue: maxValue,
            minValue: minValue,
            minStep: minStep,
            validValues: validValues,
            validValuesRange: validValuesRange) as Characteristic)
    }

    static func serialNumber(
        _ value: String = "",
        permissions: [CharacteristicPermission] = [.read],
        description: String? = "Serial Number",
        format: CharacteristicFormat? = .string,
        unit: CharacteristicUnit? = nil,
        maxLength: Int? = nil,
        maxValue: Double? = nil,
        minValue: Double? = nil,
        minStep: Double? = nil,
        validValues: [Double] = [],
        validValuesRange: Range<Double>? = nil
    ) -> AnyCharacteristic {
        return AnyCharacteristic(
            PredefinedCharacteristic.serialNumber(
            value,
            permissions: permissions,
            description: description,
            format: format,
            unit: unit,
            maxLength: maxLength,
            maxValue: maxValue,
            minValue: minValue,
            minStep: minStep,
            validValues: validValues,
            validValuesRange: validValuesRange) as Characteristic)
    }

    static func setDuration(
        _ value: UInt32 = 0,
        permissions: [CharacteristicPermission] = [.read, .write, .events],
        description: String? = "Set Duration",
        format: CharacteristicFormat? = .uint32,
        unit: CharacteristicUnit? = .seconds,
        maxLength: Int? = nil,
        maxValue: Double? = 3600,
        minValue: Double? = 0,
        minStep: Double? = 1,
        validValues: [Double] = [],
        validValuesRange: Range<Double>? = nil
    ) -> AnyCharacteristic {
        return AnyCharacteristic(
            PredefinedCharacteristic.setDuration(
            value,
            permissions: permissions,
            description: description,
            format: format,
            unit: unit,
            maxLength: maxLength,
            maxValue: maxValue,
            minValue: minValue,
            minStep: minStep,
            validValues: validValues,
            validValuesRange: validValuesRange) as Characteristic)
    }

    static func setupTransferTransport(
        _ value: Data? = nil,
        permissions: [CharacteristicPermission] = [.write],
        description: String? = "Setup Transfer Transport",
        format: CharacteristicFormat? = .tlv8,
        unit: CharacteristicUnit? = nil,
        maxLength: Int? = nil,
        maxValue: Double? = nil,
        minValue: Double? = nil,
        minStep: Double? = nil,
        validValues: [Double] = [],
        validValuesRange: Range<Double>? = nil
    ) -> AnyCharacteristic {
        return AnyCharacteristic(
            PredefinedCharacteristic.setupTransferTransport(
            value,
            permissions: permissions,
            description: description,
            format: format,
            unit: unit,
            maxLength: maxLength,
            maxValue: maxValue,
            minValue: minValue,
            minStep: minStep,
            validValues: validValues,
            validValuesRange: validValuesRange) as Characteristic)
    }

    static func signalToNoiseRatio(
        _ value: Int = 0,
        permissions: [CharacteristicPermission] = [.read],
        description: String? = "Signal-to-noise Ratio",
        format: CharacteristicFormat? = .int,
        unit: CharacteristicUnit? = nil,
        maxLength: Int? = nil,
        maxValue: Double? = nil,
        minValue: Double? = nil,
        minStep: Double? = nil,
        validValues: [Double] = [],
        validValuesRange: Range<Double>? = nil
    ) -> AnyCharacteristic {
        return AnyCharacteristic(
            PredefinedCharacteristic.signalToNoiseRatio(
            value,
            permissions: permissions,
            description: description,
            format: format,
            unit: unit,
            maxLength: maxLength,
            maxValue: maxValue,
            minValue: minValue,
            minStep: minStep,
            validValues: validValues,
            validValuesRange: validValuesRange) as Characteristic)
    }

    static func slatType(
        _ value: UInt8 = 0,
        permissions: [CharacteristicPermission] = [.read],
        description: String? = "Slat Type",
        format: CharacteristicFormat? = .uint8,
        unit: CharacteristicUnit? = nil,
        maxLength: Int? = nil,
        maxValue: Double? = 1,
        minValue: Double? = 0,
        minStep: Double? = 1,
        validValues: [Double] = [],
        validValuesRange: Range<Double>? = nil
    ) -> AnyCharacteristic {
        return AnyCharacteristic(
            PredefinedCharacteristic.slatType(
            value,
            permissions: permissions,
            description: description,
            format: format,
            unit: unit,
            maxLength: maxLength,
            maxValue: maxValue,
            minValue: minValue,
            minStep: minStep,
            validValues: validValues,
            validValuesRange: validValuesRange) as Characteristic)
    }

    static func sleepDiscoveryMode(
        _ value: Enums.SleepDiscoveryMode = .notdiscoverable,
        permissions: [CharacteristicPermission] = [.read, .events],
        description: String? = "Sleep Discovery Mode",
        format: CharacteristicFormat? = .uint8,
        unit: CharacteristicUnit? = nil,
        maxLength: Int? = nil,
        maxValue: Double? = 1,
        minValue: Double? = 0,
        minStep: Double? = 1,
        validValues: [Double] = [],
        validValuesRange: Range<Double>? = nil
    ) -> AnyCharacteristic {
        return AnyCharacteristic(
            PredefinedCharacteristic.sleepDiscoveryMode(
            value,
            permissions: permissions,
            description: description,
            format: format,
            unit: unit,
            maxLength: maxLength,
            maxValue: maxValue,
            minValue: minValue,
            minStep: minStep,
            validValues: validValues,
            validValuesRange: validValuesRange) as Characteristic)
    }

    static func sleepInterval(
        _ value: UInt32 = 0,
        permissions: [CharacteristicPermission] = [.read, .events],
        description: String? = "Sleep Interval",
        format: CharacteristicFormat? = .uint32,
        unit: CharacteristicUnit? = nil,
        maxLength: Int? = nil,
        maxValue: Double? = nil,
        minValue: Double? = 0,
        minStep: Double? = 1,
        validValues: [Double] = [],
        validValuesRange: Range<Double>? = nil
    ) -> AnyCharacteristic {
        return AnyCharacteristic(
            PredefinedCharacteristic.sleepInterval(
            value,
            permissions: permissions,
            description: description,
            format: format,
            unit: unit,
            maxLength: maxLength,
            maxValue: maxValue,
            minValue: minValue,
            minStep: minStep,
            validValues: validValues,
            validValuesRange: validValuesRange) as Characteristic)
    }

    static func smokeDetected(
        _ value: Enums.SmokeDetected = .smokedetected,
        permissions: [CharacteristicPermission] = [.read, .events],
        description: String? = "Smoke Detected",
        format: CharacteristicFormat? = .uint8,
        unit: CharacteristicUnit? = nil,
        maxLength: Int? = nil,
        maxValue: Double? = 1,
        minValue: Double? = 0,
        minStep: Double? = 1,
        validValues: [Double] = [],
        validValuesRange: Range<Double>? = nil
    ) -> AnyCharacteristic {
        return AnyCharacteristic(
            PredefinedCharacteristic.smokeDetected(
            value,
            permissions: permissions,
            description: description,
            format: format,
            unit: unit,
            maxLength: maxLength,
            maxValue: maxValue,
            minValue: minValue,
            minStep: minStep,
            validValues: validValues,
            validValuesRange: validValuesRange) as Characteristic)
    }

    static func softwareRevision(
        _ value: String = "",
        permissions: [CharacteristicPermission] = [.read],
        description: String? = "Software Revision",
        format: CharacteristicFormat? = .string,
        unit: CharacteristicUnit? = nil,
        maxLength: Int? = nil,
        maxValue: Double? = nil,
        minValue: Double? = nil,
        minStep: Double? = nil,
        validValues: [Double] = [],
        validValuesRange: Range<Double>? = nil
    ) -> AnyCharacteristic {
        return AnyCharacteristic(
            PredefinedCharacteristic.softwareRevision(
            value,
            permissions: permissions,
            description: description,
            format: format,
            unit: unit,
            maxLength: maxLength,
            maxValue: maxValue,
            minValue: minValue,
            minStep: minStep,
            validValues: validValues,
            validValuesRange: validValuesRange) as Characteristic)
    }

    static func statusActive(
        _ value: Bool = false,
        permissions: [CharacteristicPermission] = [.read, .events],
        description: String? = "Status Active",
        format: CharacteristicFormat? = .bool,
        unit: CharacteristicUnit? = nil,
        maxLength: Int? = nil,
        maxValue: Double? = nil,
        minValue: Double? = nil,
        minStep: Double? = nil,
        validValues: [Double] = [],
        validValuesRange: Range<Double>? = nil
    ) -> AnyCharacteristic {
        return AnyCharacteristic(
            PredefinedCharacteristic.statusActive(
            value,
            permissions: permissions,
            description: description,
            format: format,
            unit: unit,
            maxLength: maxLength,
            maxValue: maxValue,
            minValue: minValue,
            minStep: minStep,
            validValues: validValues,
            validValuesRange: validValuesRange) as Characteristic)
    }

    static func statusFault(
        _ value: UInt8 = 0,
        permissions: [CharacteristicPermission] = [.read, .events],
        description: String? = "Status Fault",
        format: CharacteristicFormat? = .uint8,
        unit: CharacteristicUnit? = nil,
        maxLength: Int? = nil,
        maxValue: Double? = 1,
        minValue: Double? = 0,
        minStep: Double? = 1,
        validValues: [Double] = [],
        validValuesRange: Range<Double>? = nil
    ) -> AnyCharacteristic {
        return AnyCharacteristic(
            PredefinedCharacteristic.statusFault(
            value,
            permissions: permissions,
            description: description,
            format: format,
            unit: unit,
            maxLength: maxLength,
            maxValue: maxValue,
            minValue: minValue,
            minStep: minStep,
            validValues: validValues,
            validValuesRange: validValuesRange) as Characteristic)
    }

    static func statusLowBattery(
        _ value: Enums.StatusLowBattery = .batteryNormal,
        permissions: [CharacteristicPermission] = [.read, .events],
        description: String? = "Status Low Battery",
        format: CharacteristicFormat? = .uint8,
        unit: CharacteristicUnit? = nil,
        maxLength: Int? = nil,
        maxValue: Double? = 1,
        minValue: Double? = 0,
        minStep: Double? = 1,
        validValues: [Double] = [],
        validValuesRange: Range<Double>? = nil
    ) -> AnyCharacteristic {
        return AnyCharacteristic(
            PredefinedCharacteristic.statusLowBattery(
            value,
            permissions: permissions,
            description: description,
            format: format,
            unit: unit,
            maxLength: maxLength,
            maxValue: maxValue,
            minValue: minValue,
            minStep: minStep,
            validValues: validValues,
            validValuesRange: validValuesRange) as Characteristic)
    }

    static func statusTampered(
        _ value: UInt8 = 0,
        permissions: [CharacteristicPermission] = [.read, .events],
        description: String? = "Status Tampered",
        format: CharacteristicFormat? = .uint8,
        unit: CharacteristicUnit? = nil,
        maxLength: Int? = nil,
        maxValue: Double? = 1,
        minValue: Double? = 0,
        minStep: Double? = 1,
        validValues: [Double] = [],
        validValuesRange: Range<Double>? = nil
    ) -> AnyCharacteristic {
        return AnyCharacteristic(
            PredefinedCharacteristic.statusTampered(
            value,
            permissions: permissions,
            description: description,
            format: format,
            unit: unit,
            maxLength: maxLength,
            maxValue: maxValue,
            minValue: minValue,
            minStep: minStep,
            validValues: validValues,
            validValuesRange: validValuesRange) as Characteristic)
    }

    static func sulphurDioxideDensity(
        _ value: Float = 0,
        permissions: [CharacteristicPermission] = [.read, .events],
        description: String? = "Sulphur dioxide Density",
        format: CharacteristicFormat? = .float,
        unit: CharacteristicUnit? = .microgramsPerMCubed,
        maxLength: Int? = nil,
        maxValue: Double? = 1000,
        minValue: Double? = 0,
        minStep: Double? = 1,
        validValues: [Double] = [],
        validValuesRange: Range<Double>? = nil
    ) -> AnyCharacteristic {
        return AnyCharacteristic(
            PredefinedCharacteristic.sulphurDioxideDensity(
            value,
            permissions: permissions,
            description: description,
            format: format,
            unit: unit,
            maxLength: maxLength,
            maxValue: maxValue,
            minValue: minValue,
            minStep: minStep,
            validValues: validValues,
            validValuesRange: validValuesRange) as Characteristic)
    }

    static func supportedCharacteristicValueTransitionConfiguration(
        _ value: Data = Data(),
        permissions: [CharacteristicPermission] = [.read],
        description: String? = "Supported Characteristic Value Transition Configuration",
        format: CharacteristicFormat? = .tlv8,
        unit: CharacteristicUnit? = nil,
        maxLength: Int? = nil,
        maxValue: Double? = nil,
        minValue: Double? = nil,
        minStep: Double? = nil,
        validValues: [Double] = [],
        validValuesRange: Range<Double>? = nil
    ) -> AnyCharacteristic {
        return AnyCharacteristic(
            PredefinedCharacteristic.supportedCharacteristicValueTransitionConfiguration(
            value,
            permissions: permissions,
            description: description,
            format: format,
            unit: unit,
            maxLength: maxLength,
            maxValue: maxValue,
            minValue: minValue,
            minStep: minStep,
            validValues: validValues,
            validValuesRange: validValuesRange) as Characteristic)
    }

    static func supportedDiagnosticsSnapshot(
        _ value: Data = Data(),
        permissions: [CharacteristicPermission] = [.read],
        description: String? = "Supported Diagnostics Snapshot",
        format: CharacteristicFormat? = .tlv8,
        unit: CharacteristicUnit? = nil,
        maxLength: Int? = nil,
        maxValue: Double? = nil,
        minValue: Double? = nil,
        minStep: Double? = nil,
        validValues: [Double] = [],
        validValuesRange: Range<Double>? = nil
    ) -> AnyCharacteristic {
        return AnyCharacteristic(
            PredefinedCharacteristic.supportedDiagnosticsSnapshot(
            value,
            permissions: permissions,
            description: description,
            format: format,
            unit: unit,
            maxLength: maxLength,
            maxValue: maxValue,
            minValue: minValue,
            minStep: minStep,
            validValues: validValues,
            validValuesRange: validValuesRange) as Characteristic)
    }

    static func supportedTransferTransportConfiguration(
        _ value: Data = Data(),
        permissions: [CharacteristicPermission] = [.read],
        description: String? = "Supported Transfer Transport Configuration",
        format: CharacteristicFormat? = .tlv8,
        unit: CharacteristicUnit? = nil,
        maxLength: Int? = nil,
        maxValue: Double? = nil,
        minValue: Double? = nil,
        minStep: Double? = nil,
        validValues: [Double] = [],
        validValuesRange: Range<Double>? = nil
    ) -> AnyCharacteristic {
        return AnyCharacteristic(
            PredefinedCharacteristic.supportedTransferTransportConfiguration(
            value,
            permissions: permissions,
            description: description,
            format: format,
            unit: unit,
            maxLength: maxLength,
            maxValue: maxValue,
            minValue: minValue,
            minStep: minStep,
            validValues: validValues,
            validValuesRange: validValuesRange) as Characteristic)
    }

    static func swingMode(
        _ value: UInt8 = 0,
        permissions: [CharacteristicPermission] = [.read, .write, .events],
        description: String? = "Swing Mode",
        format: CharacteristicFormat? = .uint8,
        unit: CharacteristicUnit? = nil,
        maxLength: Int? = nil,
        maxValue: Double? = 1,
        minValue: Double? = 0,
        minStep: Double? = 1,
        validValues: [Double] = [],
        validValuesRange: Range<Double>? = nil
    ) -> AnyCharacteristic {
        return AnyCharacteristic(
            PredefinedCharacteristic.swingMode(
            value,
            permissions: permissions,
            description: description,
            format: format,
            unit: unit,
            maxLength: maxLength,
            maxValue: maxValue,
            minValue: minValue,
            minStep: minStep,
            validValues: validValues,
            validValuesRange: validValuesRange) as Characteristic)
    }

    static func targetAirPurifierState(
        _ value: Enums.TargetAirPurifierState = .auto,
        permissions: [CharacteristicPermission] = [.read, .write, .events],
        description: String? = "Target Air Purifier State",
        format: CharacteristicFormat? = .uint8,
        unit: CharacteristicUnit? = nil,
        maxLength: Int? = nil,
        maxValue: Double? = 1,
        minValue: Double? = 0,
        minStep: Double? = 1,
        validValues: [Double] = [],
        validValuesRange: Range<Double>? = nil
    ) -> AnyCharacteristic {
        return AnyCharacteristic(
            PredefinedCharacteristic.targetAirPurifierState(
            value,
            permissions: permissions,
            description: description,
            format: format,
            unit: unit,
            maxLength: maxLength,
            maxValue: maxValue,
            minValue: minValue,
            minStep: minStep,
            validValues: validValues,
            validValuesRange: validValuesRange) as Characteristic)
    }

    static func targetDoorState(
        _ value: Enums.TargetDoorState = .open,
        permissions: [CharacteristicPermission] = [.read, .write, .events],
        description: String? = "Target Door State",
        format: CharacteristicFormat? = .uint8,
        unit: CharacteristicUnit? = nil,
        maxLength: Int? = nil,
        maxValue: Double? = 1,
        minValue: Double? = 0,
        minStep: Double? = 1,
        validValues: [Double] = [],
        validValuesRange: Range<Double>? = nil
    ) -> AnyCharacteristic {
        return AnyCharacteristic(
            PredefinedCharacteristic.targetDoorState(
            value,
            permissions: permissions,
            description: description,
            format: format,
            unit: unit,
            maxLength: maxLength,
            maxValue: maxValue,
            minValue: minValue,
            minStep: minStep,
            validValues: validValues,
            validValuesRange: validValuesRange) as Characteristic)
    }

    static func targetFanState(
        _ value: Enums.TargetFanState = .auto,
        permissions: [CharacteristicPermission] = [.read, .write, .events],
        description: String? = "Target Fan State",
        format: CharacteristicFormat? = .uint8,
        unit: CharacteristicUnit? = nil,
        maxLength: Int? = nil,
        maxValue: Double? = 1,
        minValue: Double? = 0,
        minStep: Double? = 1,
        validValues: [Double] = [],
        validValuesRange: Range<Double>? = nil
    ) -> AnyCharacteristic {
        return AnyCharacteristic(
            PredefinedCharacteristic.targetFanState(
            value,
            permissions: permissions,
            description: description,
            format: format,
            unit: unit,
            maxLength: maxLength,
            maxValue: maxValue,
            minValue: minValue,
            minStep: minStep,
            validValues: validValues,
            validValuesRange: validValuesRange) as Characteristic)
    }

    static func targetHeaterCoolerState(
        _ value: Enums.TargetHeaterCoolerState = .auto,
        permissions: [CharacteristicPermission] = [.read, .write, .events],
        description: String? = "Target Heater-Cooler State",
        format: CharacteristicFormat? = .uint8,
        unit: CharacteristicUnit? = nil,
        maxLength: Int? = nil,
        maxValue: Double? = 2,
        minValue: Double? = 0,
        minStep: Double? = 1,
        validValues: [Double] = [],
        validValuesRange: Range<Double>? = nil
    ) -> AnyCharacteristic {
        return AnyCharacteristic(
            PredefinedCharacteristic.targetHeaterCoolerState(
            value,
            permissions: permissions,
            description: description,
            format: format,
            unit: unit,
            maxLength: maxLength,
            maxValue: maxValue,
            minValue: minValue,
            minStep: minStep,
            validValues: validValues,
            validValuesRange: validValuesRange) as Characteristic)
    }

    static func targetHeatingCoolingState(
        _ value: Enums.TargetHeatingCoolingState = .cool,
        permissions: [CharacteristicPermission] = [.read, .write, .events],
        description: String? = "Target Heating Cooling State",
        format: CharacteristicFormat? = .uint8,
        unit: CharacteristicUnit? = nil,
        maxLength: Int? = nil,
        maxValue: Double? = 3,
        minValue: Double? = 0,
        minStep: Double? = 1,
        validValues: [Double] = [],
        validValuesRange: Range<Double>? = nil
    ) -> AnyCharacteristic {
        return AnyCharacteristic(
            PredefinedCharacteristic.targetHeatingCoolingState(
            value,
            permissions: permissions,
            description: description,
            format: format,
            unit: unit,
            maxLength: maxLength,
            maxValue: maxValue,
            minValue: minValue,
            minStep: minStep,
            validValues: validValues,
            validValuesRange: validValuesRange) as Characteristic)
    }

    static func targetHorizontalTiltAngle(
        _ value: Int = -90,
        permissions: [CharacteristicPermission] = [.read, .write, .events],
        description: String? = "Target Horizontal Tilt Angle",
        format: CharacteristicFormat? = .int,
        unit: CharacteristicUnit? = .arcdegrees,
        maxLength: Int? = nil,
        maxValue: Double? = 90,
        minValue: Double? = -90,
        minStep: Double? = 1,
        validValues: [Double] = [],
        validValuesRange: Range<Double>? = nil
    ) -> AnyCharacteristic {
        return AnyCharacteristic(
            PredefinedCharacteristic.targetHorizontalTiltAngle(
            value,
            permissions: permissions,
            description: description,
            format: format,
            unit: unit,
            maxLength: maxLength,
            maxValue: maxValue,
            minValue: minValue,
            minStep: minStep,
            validValues: validValues,
            validValuesRange: validValuesRange) as Characteristic)
    }

    static func targetHumidifierDehumidifierState(
        _ value: Enums.TargetHumidifierDehumidifierState = .auto,
        permissions: [CharacteristicPermission] = [.read, .write, .events],
        description: String? = "Target Humidifier-Dehumidifier State",
        format: CharacteristicFormat? = .uint8,
        unit: CharacteristicUnit? = nil,
        maxLength: Int? = nil,
        maxValue: Double? = 2,
        minValue: Double? = 0,
        minStep: Double? = 1,
        validValues: [Double] = [],
        validValuesRange: Range<Double>? = nil
    ) -> AnyCharacteristic {
        return AnyCharacteristic(
            PredefinedCharacteristic.targetHumidifierDehumidifierState(
            value,
            permissions: permissions,
            description: description,
            format: format,
            unit: unit,
            maxLength: maxLength,
            maxValue: maxValue,
            minValue: minValue,
            minStep: minStep,
            validValues: validValues,
            validValuesRange: validValuesRange) as Characteristic)
    }

    static func targetMediaState(
        _ value: Enums.TargetMediaState = .pause,
        permissions: [CharacteristicPermission] = [.read, .write, .events],
        description: String? = "Target Media State",
        format: CharacteristicFormat? = .uint8,
        unit: CharacteristicUnit? = nil,
        maxLength: Int? = nil,
        maxValue: Double? = 2,
        minValue: Double? = 0,
        minStep: Double? = 1,
        validValues: [Double] = [],
        validValuesRange: Range<Double>? = nil
    ) -> AnyCharacteristic {
        return AnyCharacteristic(
            PredefinedCharacteristic.targetMediaState(
            value,
            permissions: permissions,
            description: description,
            format: format,
            unit: unit,
            maxLength: maxLength,
            maxValue: maxValue,
            minValue: minValue,
            minStep: minStep,
            validValues: validValues,
            validValuesRange: validValuesRange) as Characteristic)
    }

    static func targetPosition(
        _ value: UInt8 = 0,
        permissions: [CharacteristicPermission] = [.read, .write, .events],
        description: String? = "Target Position",
        format: CharacteristicFormat? = .uint8,
        unit: CharacteristicUnit? = .percentage,
        maxLength: Int? = nil,
        maxValue: Double? = 100,
        minValue: Double? = 0,
        minStep: Double? = 1,
        validValues: [Double] = [],
        validValuesRange: Range<Double>? = nil
    ) -> AnyCharacteristic {
        return AnyCharacteristic(
            PredefinedCharacteristic.targetPosition(
            value,
            permissions: permissions,
            description: description,
            format: format,
            unit: unit,
            maxLength: maxLength,
            maxValue: maxValue,
            minValue: minValue,
            minStep: minStep,
            validValues: validValues,
            validValuesRange: validValuesRange) as Characteristic)
    }

    static func targetRelativeHumidity(
        _ value: Float = 0,
        permissions: [CharacteristicPermission] = [.read, .write, .events],
        description: String? = "Target Relative Humidity",
        format: CharacteristicFormat? = .float,
        unit: CharacteristicUnit? = .percentage,
        maxLength: Int? = nil,
        maxValue: Double? = 100,
        minValue: Double? = 0,
        minStep: Double? = 1,
        validValues: [Double] = [],
        validValuesRange: Range<Double>? = nil
    ) -> AnyCharacteristic {
        return AnyCharacteristic(
            PredefinedCharacteristic.targetRelativeHumidity(
            value,
            permissions: permissions,
            description: description,
            format: format,
            unit: unit,
            maxLength: maxLength,
            maxValue: maxValue,
            minValue: minValue,
            minStep: minStep,
            validValues: validValues,
            validValuesRange: validValuesRange) as Characteristic)
    }

    static func targetTemperature(
        _ value: Float = 10,
        permissions: [CharacteristicPermission] = [.read, .write, .events],
        description: String? = "Target Temperature",
        format: CharacteristicFormat? = .float,
        unit: CharacteristicUnit? = .celsius,
        maxLength: Int? = nil,
        maxValue: Double? = 38,
        minValue: Double? = 10,
        minStep: Double? = 0.1,
        validValues: [Double] = [],
        validValuesRange: Range<Double>? = nil
    ) -> AnyCharacteristic {
        return AnyCharacteristic(
            PredefinedCharacteristic.targetTemperature(
            value,
            permissions: permissions,
            description: description,
            format: format,
            unit: unit,
            maxLength: maxLength,
            maxValue: maxValue,
            minValue: minValue,
            minStep: minStep,
            validValues: validValues,
            validValuesRange: validValuesRange) as Characteristic)
    }

    static func targetTiltAngle(
        _ value: Int = -90,
        permissions: [CharacteristicPermission] = [.read, .write, .events],
        description: String? = "Target Tilt Angle",
        format: CharacteristicFormat? = .int,
        unit: CharacteristicUnit? = .arcdegrees,
        maxLength: Int? = nil,
        maxValue: Double? = 90,
        minValue: Double? = -90,
        minStep: Double? = 1,
        validValues: [Double] = [],
        validValuesRange: Range<Double>? = nil
    ) -> AnyCharacteristic {
        return AnyCharacteristic(
            PredefinedCharacteristic.targetTiltAngle(
            value,
            permissions: permissions,
            description: description,
            format: format,
            unit: unit,
            maxLength: maxLength,
            maxValue: maxValue,
            minValue: minValue,
            minStep: minStep,
            validValues: validValues,
            validValuesRange: validValuesRange) as Characteristic)
    }

    static func targetVerticalTiltAngle(
        _ value: Int = -90,
        permissions: [CharacteristicPermission] = [.read, .write, .events],
        description: String? = "Target Vertical Tilt Angle",
        format: CharacteristicFormat? = .int,
        unit: CharacteristicUnit? = .arcdegrees,
        maxLength: Int? = nil,
        maxValue: Double? = 90,
        minValue: Double? = -90,
        minStep: Double? = 1,
        validValues: [Double] = [],
        validValuesRange: Range<Double>? = nil
    ) -> AnyCharacteristic {
        return AnyCharacteristic(
            PredefinedCharacteristic.targetVerticalTiltAngle(
            value,
            permissions: permissions,
            description: description,
            format: format,
            unit: unit,
            maxLength: maxLength,
            maxValue: maxValue,
            minValue: minValue,
            minStep: minStep,
            validValues: validValues,
            validValuesRange: validValuesRange) as Characteristic)
    }

    static func targetVisibilityState(
        _ value: Enums.TargetVisibilityState = .shown,
        permissions: [CharacteristicPermission] = [.read, .write, .events],
        description: String? = "Target Visibility State",
        format: CharacteristicFormat? = .uint8,
        unit: CharacteristicUnit? = nil,
        maxLength: Int? = nil,
        maxValue: Double? = 1,
        minValue: Double? = 0,
        minStep: Double? = 1,
        validValues: [Double] = [],
        validValuesRange: Range<Double>? = nil
    ) -> AnyCharacteristic {
        return AnyCharacteristic(
            PredefinedCharacteristic.targetVisibilityState(
            value,
            permissions: permissions,
            description: description,
            format: format,
            unit: unit,
            maxLength: maxLength,
            maxValue: maxValue,
            minValue: minValue,
            minStep: minStep,
            validValues: validValues,
            validValuesRange: validValuesRange) as Characteristic)
    }

    static func temperatureDisplayUnits(
        _ value: Enums.TemperatureDisplayUnits = .celcius,
        permissions: [CharacteristicPermission] = [.read, .write, .events],
        description: String? = "Temperature Display Units",
        format: CharacteristicFormat? = .uint8,
        unit: CharacteristicUnit? = nil,
        maxLength: Int? = nil,
        maxValue: Double? = 1,
        minValue: Double? = 0,
        minStep: Double? = 1,
        validValues: [Double] = [],
        validValuesRange: Range<Double>? = nil
    ) -> AnyCharacteristic {
        return AnyCharacteristic(
            PredefinedCharacteristic.temperatureDisplayUnits(
            value,
            permissions: permissions,
            description: description,
            format: format,
            unit: unit,
            maxLength: maxLength,
            maxValue: maxValue,
            minValue: minValue,
            minStep: minStep,
            validValues: validValues,
            validValuesRange: validValuesRange) as Characteristic)
    }

    static func threadControlPoint(
        _ value: Data? = nil,
        permissions: [CharacteristicPermission] = [.write],
        description: String? = "Thread Control Point",
        format: CharacteristicFormat? = .tlv8,
        unit: CharacteristicUnit? = nil,
        maxLength: Int? = nil,
        maxValue: Double? = nil,
        minValue: Double? = nil,
        minStep: Double? = nil,
        validValues: [Double] = [],
        validValuesRange: Range<Double>? = nil
    ) -> AnyCharacteristic {
        return AnyCharacteristic(
            PredefinedCharacteristic.threadControlPoint(
            value,
            permissions: permissions,
            description: description,
            format: format,
            unit: unit,
            maxLength: maxLength,
            maxValue: maxValue,
            minValue: minValue,
            minStep: minStep,
            validValues: validValues,
            validValuesRange: validValuesRange) as Characteristic)
    }

    static func threadNodeCapabilities(
        _ value: UInt16 = 0,
        permissions: [CharacteristicPermission] = [.read],
        description: String? = "Thread Node Capabilities",
        format: CharacteristicFormat? = .uint16,
        unit: CharacteristicUnit? = nil,
        maxLength: Int? = nil,
        maxValue: Double? = 31,
        minValue: Double? = 0,
        minStep: Double? = 1,
        validValues: [Double] = [],
        validValuesRange: Range<Double>? = nil
    ) -> AnyCharacteristic {
        return AnyCharacteristic(
            PredefinedCharacteristic.threadNodeCapabilities(
            value,
            permissions: permissions,
            description: description,
            format: format,
            unit: unit,
            maxLength: maxLength,
            maxValue: maxValue,
            minValue: minValue,
            minStep: minStep,
            validValues: validValues,
            validValuesRange: validValuesRange) as Characteristic)
    }

    static func threadOpenthreadVersion(
        _ value: String = "",
        permissions: [CharacteristicPermission] = [.read],
        description: String? = "Thread OpenThread Version",
        format: CharacteristicFormat? = .string,
        unit: CharacteristicUnit? = nil,
        maxLength: Int? = nil,
        maxValue: Double? = nil,
        minValue: Double? = nil,
        minStep: Double? = nil,
        validValues: [Double] = [],
        validValuesRange: Range<Double>? = nil
    ) -> AnyCharacteristic {
        return AnyCharacteristic(
            PredefinedCharacteristic.threadOpenthreadVersion(
            value,
            permissions: permissions,
            description: description,
            format: format,
            unit: unit,
            maxLength: maxLength,
            maxValue: maxValue,
            minValue: minValue,
            minStep: minStep,
            validValues: validValues,
            validValuesRange: validValuesRange) as Characteristic)
    }

    static func threadStatus(
        _ value: UInt16 = 0,
        permissions: [CharacteristicPermission] = [.read, .events],
        description: String? = "Thread Status",
        format: CharacteristicFormat? = .uint16,
        unit: CharacteristicUnit? = nil,
        maxLength: Int? = nil,
        maxValue: Double? = 6,
        minValue: Double? = 0,
        minStep: Double? = 1,
        validValues: [Double] = [],
        validValuesRange: Range<Double>? = nil
    ) -> AnyCharacteristic {
        return AnyCharacteristic(
            PredefinedCharacteristic.threadStatus(
            value,
            permissions: permissions,
            description: description,
            format: format,
            unit: unit,
            maxLength: maxLength,
            maxValue: maxValue,
            minValue: minValue,
            minStep: minStep,
            validValues: validValues,
            validValuesRange: validValuesRange) as Characteristic)
    }

    static func transmitPower(
        _ value: Int = 0,
        permissions: [CharacteristicPermission] = [.read],
        description: String? = "Transmit Power",
        format: CharacteristicFormat? = .int,
        unit: CharacteristicUnit? = nil,
        maxLength: Int? = nil,
        maxValue: Double? = nil,
        minValue: Double? = nil,
        minStep: Double? = nil,
        validValues: [Double] = [],
        validValuesRange: Range<Double>? = nil
    ) -> AnyCharacteristic {
        return AnyCharacteristic(
            PredefinedCharacteristic.transmitPower(
            value,
            permissions: permissions,
            description: description,
            format: format,
            unit: unit,
            maxLength: maxLength,
            maxValue: maxValue,
            minValue: minValue,
            minStep: minStep,
            validValues: validValues,
            validValuesRange: validValuesRange) as Characteristic)
    }

    static func valveType(
        _ value: UInt8 = 0,
        permissions: [CharacteristicPermission] = [.read, .events],
        description: String? = "Valve Type",
        format: CharacteristicFormat? = .uint8,
        unit: CharacteristicUnit? = nil,
        maxLength: Int? = nil,
        maxValue: Double? = 3,
        minValue: Double? = 0,
        minStep: Double? = 1,
        validValues: [Double] = [],
        validValuesRange: Range<Double>? = nil
    ) -> AnyCharacteristic {
        return AnyCharacteristic(
            PredefinedCharacteristic.valveType(
            value,
            permissions: permissions,
            description: description,
            format: format,
            unit: unit,
            maxLength: maxLength,
            maxValue: maxValue,
            minValue: minValue,
            minStep: minStep,
            validValues: validValues,
            validValuesRange: validValuesRange) as Characteristic)
    }

    static func version(
        _ value: String = "",
        permissions: [CharacteristicPermission] = [.read, .events],
        description: String? = "Version",
        format: CharacteristicFormat? = .string,
        unit: CharacteristicUnit? = nil,
        maxLength: Int? = nil,
        maxValue: Double? = nil,
        minValue: Double? = nil,
        minStep: Double? = nil,
        validValues: [Double] = [],
        validValuesRange: Range<Double>? = nil
    ) -> AnyCharacteristic {
        return AnyCharacteristic(
            PredefinedCharacteristic.version(
            value,
            permissions: permissions,
            description: description,
            format: format,
            unit: unit,
            maxLength: maxLength,
            maxValue: maxValue,
            minValue: minValue,
            minStep: minStep,
            validValues: validValues,
            validValuesRange: validValuesRange) as Characteristic)
    }

    static func volatileOrganicCompoundDensity(
        _ value: Float = 0,
        permissions: [CharacteristicPermission] = [.read, .events],
        description: String? = "Volatile Organic Compound Density",
        format: CharacteristicFormat? = .float,
        unit: CharacteristicUnit? = .microgramsPerMCubed,
        maxLength: Int? = nil,
        maxValue: Double? = 1000,
        minValue: Double? = 0,
        minStep: Double? = 1,
        validValues: [Double] = [],
        validValuesRange: Range<Double>? = nil
    ) -> AnyCharacteristic {
        return AnyCharacteristic(
            PredefinedCharacteristic.volatileOrganicCompoundDensity(
            value,
            permissions: permissions,
            description: description,
            format: format,
            unit: unit,
            maxLength: maxLength,
            maxValue: maxValue,
            minValue: minValue,
            minStep: minStep,
            validValues: validValues,
            validValuesRange: validValuesRange) as Characteristic)
    }

    static func volume(
        _ value: UInt8 = 0,
        permissions: [CharacteristicPermission] = [.read, .write, .events],
        description: String? = "Volume",
        format: CharacteristicFormat? = .uint8,
        unit: CharacteristicUnit? = .percentage,
        maxLength: Int? = nil,
        maxValue: Double? = 100,
        minValue: Double? = 0,
        minStep: Double? = 1,
        validValues: [Double] = [],
        validValuesRange: Range<Double>? = nil
    ) -> AnyCharacteristic {
        return AnyCharacteristic(
            PredefinedCharacteristic.volume(
            value,
            permissions: permissions,
            description: description,
            format: format,
            unit: unit,
            maxLength: maxLength,
            maxValue: maxValue,
            minValue: minValue,
            minStep: minStep,
            validValues: validValues,
            validValuesRange: validValuesRange) as Characteristic)
    }

    static func volumeControlType(
        _ value: Enums.VolumeControlType = .relativewithcurrent,
        permissions: [CharacteristicPermission] = [.read, .events],
        description: String? = "Volume Control Type",
        format: CharacteristicFormat? = .uint8,
        unit: CharacteristicUnit? = nil,
        maxLength: Int? = nil,
        maxValue: Double? = 3,
        minValue: Double? = 0,
        minStep: Double? = 1,
        validValues: [Double] = [],
        validValuesRange: Range<Double>? = nil
    ) -> AnyCharacteristic {
        return AnyCharacteristic(
            PredefinedCharacteristic.volumeControlType(
            value,
            permissions: permissions,
            description: description,
            format: format,
            unit: unit,
            maxLength: maxLength,
            maxValue: maxValue,
            minValue: minValue,
            minStep: minStep,
            validValues: validValues,
            validValuesRange: validValuesRange) as Characteristic)
    }

    static func volumeSelector(
        _ value: Enums.VolumeSelector? = nil,
        permissions: [CharacteristicPermission] = [.write],
        description: String? = "Volume Selector",
        format: CharacteristicFormat? = .uint8,
        unit: CharacteristicUnit? = nil,
        maxLength: Int? = nil,
        maxValue: Double? = 1,
        minValue: Double? = 0,
        minStep: Double? = 1,
        validValues: [Double] = [],
        validValuesRange: Range<Double>? = nil
    ) -> AnyCharacteristic {
        return AnyCharacteristic(
            PredefinedCharacteristic.volumeSelector(
            value,
            permissions: permissions,
            description: description,
            format: format,
            unit: unit,
            maxLength: maxLength,
            maxValue: maxValue,
            minValue: minValue,
            minStep: minStep,
            validValues: validValues,
            validValuesRange: validValuesRange) as Characteristic)
    }

    static func wiFiCapabilities(
        _ value: UInt32 = 0,
        permissions: [CharacteristicPermission] = [.read],
        description: String? = "Wi-Fi Capabilities",
        format: CharacteristicFormat? = .uint32,
        unit: CharacteristicUnit? = nil,
        maxLength: Int? = nil,
        maxValue: Double? = nil,
        minValue: Double? = nil,
        minStep: Double? = nil,
        validValues: [Double] = [],
        validValuesRange: Range<Double>? = nil
    ) -> AnyCharacteristic {
        return AnyCharacteristic(
            PredefinedCharacteristic.wiFiCapabilities(
            value,
            permissions: permissions,
            description: description,
            format: format,
            unit: unit,
            maxLength: maxLength,
            maxValue: maxValue,
            minValue: minValue,
            minStep: minStep,
            validValues: validValues,
            validValuesRange: validValuesRange) as Characteristic)
    }

    static func wiFiConfigurationControl(
        _ value: Data = Data(),
        permissions: [CharacteristicPermission] = [.read, .write, .events],
        description: String? = "Wi-Fi Configuration Control",
        format: CharacteristicFormat? = .tlv8,
        unit: CharacteristicUnit? = nil,
        maxLength: Int? = nil,
        maxValue: Double? = nil,
        minValue: Double? = nil,
        minStep: Double? = nil,
        validValues: [Double] = [],
        validValuesRange: Range<Double>? = nil
    ) -> AnyCharacteristic {
        return AnyCharacteristic(
            PredefinedCharacteristic.wiFiConfigurationControl(
            value,
            permissions: permissions,
            description: description,
            format: format,
            unit: unit,
            maxLength: maxLength,
            maxValue: maxValue,
            minValue: minValue,
            minStep: minStep,
            validValues: validValues,
            validValuesRange: validValuesRange) as Characteristic)
    }

}

public class PredefinedCharacteristic {
    static func accessoryFlags(
        _ value: UInt32 = 0,
        permissions: [CharacteristicPermission] = [.read, .events],
        description: String? = "Accessory Flags",
        format: CharacteristicFormat? = .uint32,
        unit: CharacteristicUnit? = nil,
        maxLength: Int? = nil,
        maxValue: Double? = nil,
        minValue: Double? = nil,
        minStep: Double? = nil,
        validValues: [Double] = [],
        validValuesRange: Range<Double>? = nil
    ) -> GenericCharacteristic<UInt32> {
        return GenericCharacteristic<UInt32>(
            type: .accessoryFlags,
            value: value,
            permissions: permissions,
            description: description,
            format: format,
            unit: unit,
            maxLength: maxLength,
            maxValue: maxValue,
            minValue: minValue,
            minStep: minStep,
            validValues: validValues,
            validValuesRange: validValuesRange)
    }

    static func active(
        _ value: Enums.Active = .active,
        permissions: [CharacteristicPermission] = [.read, .write, .events],
        description: String? = "Active",
        format: CharacteristicFormat? = .uint8,
        unit: CharacteristicUnit? = nil,
        maxLength: Int? = nil,
        maxValue: Double? = 1,
        minValue: Double? = 0,
        minStep: Double? = 1,
        validValues: [Double] = [],
        validValuesRange: Range<Double>? = nil
    ) -> GenericCharacteristic<Enums.Active> {
        return GenericCharacteristic<Enums.Active>(
            type: .active,
            value: value,
            permissions: permissions,
            description: description,
            format: format,
            unit: unit,
            maxLength: maxLength,
            maxValue: maxValue,
            minValue: minValue,
            minStep: minStep,
            validValues: validValues,
            validValuesRange: validValuesRange)
    }

    static func activeIdentifier(
        _ value: UInt32 = 0,
        permissions: [CharacteristicPermission] = [.read, .write, .events],
        description: String? = "Active Identifier",
        format: CharacteristicFormat? = .uint32,
        unit: CharacteristicUnit? = nil,
        maxLength: Int? = nil,
        maxValue: Double? = nil,
        minValue: Double? = 0,
        minStep: Double? = nil,
        validValues: [Double] = [],
        validValuesRange: Range<Double>? = nil
    ) -> GenericCharacteristic<UInt32> {
        return GenericCharacteristic<UInt32>(
            type: .activeIdentifier,
            value: value,
            permissions: permissions,
            description: description,
            format: format,
            unit: unit,
            maxLength: maxLength,
            maxValue: maxValue,
            minValue: minValue,
            minStep: minStep,
            validValues: validValues,
            validValuesRange: validValuesRange)
    }

    static func administratorOnlyAccess(
        _ value: Bool = false,
        permissions: [CharacteristicPermission] = [.read, .write, .events],
        description: String? = "Administrator Only Access",
        format: CharacteristicFormat? = .bool,
        unit: CharacteristicUnit? = nil,
        maxLength: Int? = nil,
        maxValue: Double? = nil,
        minValue: Double? = nil,
        minStep: Double? = nil,
        validValues: [Double] = [],
        validValuesRange: Range<Double>? = nil
    ) -> GenericCharacteristic<Bool> {
        return GenericCharacteristic<Bool>(
            type: .administratorOnlyAccess,
            value: value,
            permissions: permissions,
            description: description,
            format: format,
            unit: unit,
            maxLength: maxLength,
            maxValue: maxValue,
            minValue: minValue,
            minStep: minStep,
            validValues: validValues,
            validValuesRange: validValuesRange)
    }

    static func applicationMatchingIdentifier(
        _ value: Data = Data(),
        permissions: [CharacteristicPermission] = [.read],
        description: String? = "Application Matching Identifier",
        format: CharacteristicFormat? = .tlv8,
        unit: CharacteristicUnit? = nil,
        maxLength: Int? = nil,
        maxValue: Double? = nil,
        minValue: Double? = nil,
        minStep: Double? = nil,
        validValues: [Double] = [],
        validValuesRange: Range<Double>? = nil
    ) -> GenericCharacteristic<Data> {
        return GenericCharacteristic<Data>(
            type: .applicationMatchingIdentifier,
            value: value,
            permissions: permissions,
            description: description,
            format: format,
            unit: unit,
            maxLength: maxLength,
            maxValue: maxValue,
            minValue: minValue,
            minStep: minStep,
            validValues: validValues,
            validValuesRange: validValuesRange)
    }

    static func audioFeedback(
        _ value: Bool = false,
        permissions: [CharacteristicPermission] = [.read, .write, .events],
        description: String? = "Audio Feedback",
        format: CharacteristicFormat? = .bool,
        unit: CharacteristicUnit? = nil,
        maxLength: Int? = nil,
        maxValue: Double? = nil,
        minValue: Double? = nil,
        minStep: Double? = nil,
        validValues: [Double] = [],
        validValuesRange: Range<Double>? = nil
    ) -> GenericCharacteristic<Bool> {
        return GenericCharacteristic<Bool>(
            type: .audioFeedback,
            value: value,
            permissions: permissions,
            description: description,
            format: format,
            unit: unit,
            maxLength: maxLength,
            maxValue: maxValue,
            minValue: minValue,
            minStep: minStep,
            validValues: validValues,
            validValuesRange: validValuesRange)
    }

    static func batteryLevel(
        _ value: UInt8 = 0,
        permissions: [CharacteristicPermission] = [.read, .events],
        description: String? = "Battery Level",
        format: CharacteristicFormat? = .uint8,
        unit: CharacteristicUnit? = .percentage,
        maxLength: Int? = nil,
        maxValue: Double? = 100,
        minValue: Double? = 0,
        minStep: Double? = 1,
        validValues: [Double] = [],
        validValuesRange: Range<Double>? = nil
    ) -> GenericCharacteristic<UInt8> {
        return GenericCharacteristic<UInt8>(
            type: .batteryLevel,
            value: value,
            permissions: permissions,
            description: description,
            format: format,
            unit: unit,
            maxLength: maxLength,
            maxValue: maxValue,
            minValue: minValue,
            minStep: minStep,
            validValues: validValues,
            validValuesRange: validValuesRange)
    }

    static func brightness(
        _ value: Int = 0,
        permissions: [CharacteristicPermission] = [.read, .write, .events],
        description: String? = "Brightness",
        format: CharacteristicFormat? = .int,
        unit: CharacteristicUnit? = .percentage,
        maxLength: Int? = nil,
        maxValue: Double? = 100,
        minValue: Double? = 0,
        minStep: Double? = 1,
        validValues: [Double] = [],
        validValuesRange: Range<Double>? = nil
    ) -> GenericCharacteristic<Int> {
        return GenericCharacteristic<Int>(
            type: .brightness,
            value: value,
            permissions: permissions,
            description: description,
            format: format,
            unit: unit,
            maxLength: maxLength,
            maxValue: maxValue,
            minValue: minValue,
            minStep: minStep,
            validValues: validValues,
            validValuesRange: validValuesRange)
    }

    static func ccaEnergyDetectThreshold(
        _ value: Int = 0,
        permissions: [CharacteristicPermission] = [.read],
        description: String? = "CCA Energy Detect Threshold",
        format: CharacteristicFormat? = .int,
        unit: CharacteristicUnit? = nil,
        maxLength: Int? = nil,
        maxValue: Double? = nil,
        minValue: Double? = nil,
        minStep: Double? = nil,
        validValues: [Double] = [],
        validValuesRange: Range<Double>? = nil
    ) -> GenericCharacteristic<Int> {
        return GenericCharacteristic<Int>(
            type: .ccaEnergyDetectThreshold,
            value: value,
            permissions: permissions,
            description: description,
            format: format,
            unit: unit,
            maxLength: maxLength,
            maxValue: maxValue,
            minValue: minValue,
            minStep: minStep,
            validValues: validValues,
            validValuesRange: validValuesRange)
    }

    static func ccaSignalDetectThreshold(
        _ value: Int = 0,
        permissions: [CharacteristicPermission] = [.read],
        description: String? = "CCA Signal Detect Threshold",
        format: CharacteristicFormat? = .int,
        unit: CharacteristicUnit? = nil,
        maxLength: Int? = nil,
        maxValue: Double? = nil,
        minValue: Double? = nil,
        minStep: Double? = nil,
        validValues: [Double] = [],
        validValuesRange: Range<Double>? = nil
    ) -> GenericCharacteristic<Int> {
        return GenericCharacteristic<Int>(
            type: .ccaSignalDetectThreshold,
            value: value,
            permissions: permissions,
            description: description,
            format: format,
            unit: unit,
            maxLength: maxLength,
            maxValue: maxValue,
            minValue: minValue,
            minStep: minStep,
            validValues: validValues,
            validValuesRange: validValuesRange)
    }

    static func carbonDioxideDetected(
        _ value: Enums.CarbonDioxideDetected = .normal,
        permissions: [CharacteristicPermission] = [.read, .events],
        description: String? = "Carbon dioxide Detected",
        format: CharacteristicFormat? = .uint8,
        unit: CharacteristicUnit? = nil,
        maxLength: Int? = nil,
        maxValue: Double? = 1,
        minValue: Double? = 0,
        minStep: Double? = 1,
        validValues: [Double] = [],
        validValuesRange: Range<Double>? = nil
    ) -> GenericCharacteristic<Enums.CarbonDioxideDetected> {
        return GenericCharacteristic<Enums.CarbonDioxideDetected>(
            type: .carbonDioxideDetected,
            value: value,
            permissions: permissions,
            description: description,
            format: format,
            unit: unit,
            maxLength: maxLength,
            maxValue: maxValue,
            minValue: minValue,
            minStep: minStep,
            validValues: validValues,
            validValuesRange: validValuesRange)
    }

    static func carbonDioxideLevel(
        _ value: Float = 0,
        permissions: [CharacteristicPermission] = [.read, .events],
        description: String? = "Carbon dioxide Level",
        format: CharacteristicFormat? = .float,
        unit: CharacteristicUnit? = .ppm,
        maxLength: Int? = nil,
        maxValue: Double? = 100000,
        minValue: Double? = 0,
        minStep: Double? = 1,
        validValues: [Double] = [],
        validValuesRange: Range<Double>? = nil
    ) -> GenericCharacteristic<Float> {
        return GenericCharacteristic<Float>(
            type: .carbonDioxideLevel,
            value: value,
            permissions: permissions,
            description: description,
            format: format,
            unit: unit,
            maxLength: maxLength,
            maxValue: maxValue,
            minValue: minValue,
            minStep: minStep,
            validValues: validValues,
            validValuesRange: validValuesRange)
    }

    static func carbonDioxidePeakLevel(
        _ value: Float = 0,
        permissions: [CharacteristicPermission] = [.read, .events],
        description: String? = "Carbon dioxide Peak Level",
        format: CharacteristicFormat? = .float,
        unit: CharacteristicUnit? = .ppm,
        maxLength: Int? = nil,
        maxValue: Double? = 100000,
        minValue: Double? = 0,
        minStep: Double? = 1,
        validValues: [Double] = [],
        validValuesRange: Range<Double>? = nil
    ) -> GenericCharacteristic<Float> {
        return GenericCharacteristic<Float>(
            type: .carbonDioxidePeakLevel,
            value: value,
            permissions: permissions,
            description: description,
            format: format,
            unit: unit,
            maxLength: maxLength,
            maxValue: maxValue,
            minValue: minValue,
            minStep: minStep,
            validValues: validValues,
            validValuesRange: validValuesRange)
    }

    static func carbonMonoxideDetected(
        _ value: UInt8 = 0,
        permissions: [CharacteristicPermission] = [.read, .events],
        description: String? = "Carbon monoxide Detected",
        format: CharacteristicFormat? = .uint8,
        unit: CharacteristicUnit? = nil,
        maxLength: Int? = nil,
        maxValue: Double? = 1,
        minValue: Double? = 0,
        minStep: Double? = 1,
        validValues: [Double] = [],
        validValuesRange: Range<Double>? = nil
    ) -> GenericCharacteristic<UInt8> {
        return GenericCharacteristic<UInt8>(
            type: .carbonMonoxideDetected,
            value: value,
            permissions: permissions,
            description: description,
            format: format,
            unit: unit,
            maxLength: maxLength,
            maxValue: maxValue,
            minValue: minValue,
            minStep: minStep,
            validValues: validValues,
            validValuesRange: validValuesRange)
    }

    static func carbonMonoxideLevel(
        _ value: Float = 0,
        permissions: [CharacteristicPermission] = [.read, .events],
        description: String? = "Carbon monoxide Level",
        format: CharacteristicFormat? = .float,
        unit: CharacteristicUnit? = .ppm,
        maxLength: Int? = nil,
        maxValue: Double? = 100,
        minValue: Double? = 0,
        minStep: Double? = 1,
        validValues: [Double] = [],
        validValuesRange: Range<Double>? = nil
    ) -> GenericCharacteristic<Float> {
        return GenericCharacteristic<Float>(
            type: .carbonMonoxideLevel,
            value: value,
            permissions: permissions,
            description: description,
            format: format,
            unit: unit,
            maxLength: maxLength,
            maxValue: maxValue,
            minValue: minValue,
            minStep: minStep,
            validValues: validValues,
            validValuesRange: validValuesRange)
    }

    static func carbonMonoxidePeakLevel(
        _ value: Float = 0,
        permissions: [CharacteristicPermission] = [.read, .events],
        description: String? = "Carbon monoxide Peak Level",
        format: CharacteristicFormat? = .float,
        unit: CharacteristicUnit? = .ppm,
        maxLength: Int? = nil,
        maxValue: Double? = 100,
        minValue: Double? = 0,
        minStep: Double? = 1,
        validValues: [Double] = [],
        validValuesRange: Range<Double>? = nil
    ) -> GenericCharacteristic<Float> {
        return GenericCharacteristic<Float>(
            type: .carbonMonoxidePeakLevel,
            value: value,
            permissions: permissions,
            description: description,
            format: format,
            unit: unit,
            maxLength: maxLength,
            maxValue: maxValue,
            minValue: minValue,
            minStep: minStep,
            validValues: validValues,
            validValuesRange: validValuesRange)
    }

    static func characteristicValueActiveTransitionCount(
        _ value: UInt8 = 0,
        permissions: [CharacteristicPermission] = [.read, .events],
        description: String? = "Characteristic Value Active Transition Count",
        format: CharacteristicFormat? = .uint8,
        unit: CharacteristicUnit? = nil,
        maxLength: Int? = nil,
        maxValue: Double? = nil,
        minValue: Double? = nil,
        minStep: Double? = nil,
        validValues: [Double] = [],
        validValuesRange: Range<Double>? = nil
    ) -> GenericCharacteristic<UInt8> {
        return GenericCharacteristic<UInt8>(
            type: .characteristicValueActiveTransitionCount,
            value: value,
            permissions: permissions,
            description: description,
            format: format,
            unit: unit,
            maxLength: maxLength,
            maxValue: maxValue,
            minValue: minValue,
            minStep: minStep,
            validValues: validValues,
            validValuesRange: validValuesRange)
    }

    static func characteristicValueTransitionControl(
        _ value: Data = Data(),
        permissions: [CharacteristicPermission] = [.read, .write],
        description: String? = "Characteristic Value Transition Control",
        format: CharacteristicFormat? = .tlv8,
        unit: CharacteristicUnit? = nil,
        maxLength: Int? = nil,
        maxValue: Double? = nil,
        minValue: Double? = nil,
        minStep: Double? = nil,
        validValues: [Double] = [],
        validValuesRange: Range<Double>? = nil
    ) -> GenericCharacteristic<Data> {
        return GenericCharacteristic<Data>(
            type: .characteristicValueTransitionControl,
            value: value,
            permissions: permissions,
            description: description,
            format: format,
            unit: unit,
            maxLength: maxLength,
            maxValue: maxValue,
            minValue: minValue,
            minStep: minStep,
            validValues: validValues,
            validValuesRange: validValuesRange)
    }

    static func chargingState(
        _ value: Enums.ChargingState = .notChargeable,
        permissions: [CharacteristicPermission] = [.read, .events],
        description: String? = "Charging State",
        format: CharacteristicFormat? = .uint8,
        unit: CharacteristicUnit? = nil,
        maxLength: Int? = nil,
        maxValue: Double? = 2,
        minValue: Double? = 0,
        minStep: Double? = 1,
        validValues: [Double] = [],
        validValuesRange: Range<Double>? = nil
    ) -> GenericCharacteristic<Enums.ChargingState> {
        return GenericCharacteristic<Enums.ChargingState>(
            type: .chargingState,
            value: value,
            permissions: permissions,
            description: description,
            format: format,
            unit: unit,
            maxLength: maxLength,
            maxValue: maxValue,
            minValue: minValue,
            minStep: minStep,
            validValues: validValues,
            validValuesRange: validValuesRange)
    }

    static func closedCaptions(
        _ value: Enums.ClosedCaptions = .enabled,
        permissions: [CharacteristicPermission] = [.read, .write, .events],
        description: String? = "Closed Captions",
        format: CharacteristicFormat? = .uint8,
        unit: CharacteristicUnit? = nil,
        maxLength: Int? = nil,
        maxValue: Double? = 1,
        minValue: Double? = 0,
        minStep: Double? = 1,
        validValues: [Double] = [],
        validValuesRange: Range<Double>? = nil
    ) -> GenericCharacteristic<Enums.ClosedCaptions> {
        return GenericCharacteristic<Enums.ClosedCaptions>(
            type: .closedCaptions,
            value: value,
            permissions: permissions,
            description: description,
            format: format,
            unit: unit,
            maxLength: maxLength,
            maxValue: maxValue,
            minValue: minValue,
            minStep: minStep,
            validValues: validValues,
            validValuesRange: validValuesRange)
    }

    static func colorTemperature(
        _ value: Int = 140,
        permissions: [CharacteristicPermission] = [.read, .write, .events],
        description: String? = "Color Temperature",
        format: CharacteristicFormat? = .int,
        unit: CharacteristicUnit? = nil,
        maxLength: Int? = nil,
        maxValue: Double? = 500,
        minValue: Double? = 140,
        minStep: Double? = 1,
        validValues: [Double] = [],
        validValuesRange: Range<Double>? = nil
    ) -> GenericCharacteristic<Int> {
        return GenericCharacteristic<Int>(
            type: .colorTemperature,
            value: value,
            permissions: permissions,
            description: description,
            format: format,
            unit: unit,
            maxLength: maxLength,
            maxValue: maxValue,
            minValue: minValue,
            minStep: minStep,
            validValues: validValues,
            validValuesRange: validValuesRange)
    }

    static func configuredName(
        _ value: String = "",
        permissions: [CharacteristicPermission] = [.read, .events],
        description: String? = "Configured Name",
        format: CharacteristicFormat? = .string,
        unit: CharacteristicUnit? = nil,
        maxLength: Int? = nil,
        maxValue: Double? = nil,
        minValue: Double? = nil,
        minStep: Double? = nil,
        validValues: [Double] = [],
        validValuesRange: Range<Double>? = nil
    ) -> GenericCharacteristic<String> {
        return GenericCharacteristic<String>(
            type: .configuredName,
            value: value,
            permissions: permissions,
            description: description,
            format: format,
            unit: unit,
            maxLength: maxLength,
            maxValue: maxValue,
            minValue: minValue,
            minStep: minStep,
            validValues: validValues,
            validValuesRange: validValuesRange)
    }

    static func contactSensorState(
        _ value: Enums.ContactSensorState = .detected,
        permissions: [CharacteristicPermission] = [.read, .events],
        description: String? = "Contact Sensor State",
        format: CharacteristicFormat? = .uint8,
        unit: CharacteristicUnit? = nil,
        maxLength: Int? = nil,
        maxValue: Double? = 1,
        minValue: Double? = 0,
        minStep: Double? = 1,
        validValues: [Double] = [],
        validValuesRange: Range<Double>? = nil
    ) -> GenericCharacteristic<Enums.ContactSensorState> {
        return GenericCharacteristic<Enums.ContactSensorState>(
            type: .contactSensorState,
            value: value,
            permissions: permissions,
            description: description,
            format: format,
            unit: unit,
            maxLength: maxLength,
            maxValue: maxValue,
            minValue: minValue,
            minStep: minStep,
            validValues: validValues,
            validValuesRange: validValuesRange)
    }

    static func coolingThresholdTemperature(
        _ value: Float = 10,
        permissions: [CharacteristicPermission] = [.read, .write, .events],
        description: String? = "Cooling Threshold Temperature",
        format: CharacteristicFormat? = .float,
        unit: CharacteristicUnit? = .celsius,
        maxLength: Int? = nil,
        maxValue: Double? = 35,
        minValue: Double? = 10,
        minStep: Double? = 0.1,
        validValues: [Double] = [],
        validValuesRange: Range<Double>? = nil
    ) -> GenericCharacteristic<Float> {
        return GenericCharacteristic<Float>(
            type: .coolingThresholdTemperature,
            value: value,
            permissions: permissions,
            description: description,
            format: format,
            unit: unit,
            maxLength: maxLength,
            maxValue: maxValue,
            minValue: minValue,
            minStep: minStep,
            validValues: validValues,
            validValuesRange: validValuesRange)
    }

    static func currentAirPurifierState(
        _ value: Enums.CurrentAirPurifierState = .inactive,
        permissions: [CharacteristicPermission] = [.read, .events],
        description: String? = "Current Air Purifier State",
        format: CharacteristicFormat? = .uint8,
        unit: CharacteristicUnit? = nil,
        maxLength: Int? = nil,
        maxValue: Double? = 2,
        minValue: Double? = 0,
        minStep: Double? = 1,
        validValues: [Double] = [],
        validValuesRange: Range<Double>? = nil
    ) -> GenericCharacteristic<Enums.CurrentAirPurifierState> {
        return GenericCharacteristic<Enums.CurrentAirPurifierState>(
            type: .currentAirPurifierState,
            value: value,
            permissions: permissions,
            description: description,
            format: format,
            unit: unit,
            maxLength: maxLength,
            maxValue: maxValue,
            minValue: minValue,
            minStep: minStep,
            validValues: validValues,
            validValuesRange: validValuesRange)
    }

    static func currentAirQuality(
        _ value: Enums.CurrentAirQuality = .good,
        permissions: [CharacteristicPermission] = [.read, .events],
        description: String? = "Current Air Quality",
        format: CharacteristicFormat? = .uint8,
        unit: CharacteristicUnit? = nil,
        maxLength: Int? = nil,
        maxValue: Double? = 5,
        minValue: Double? = 0,
        minStep: Double? = 1,
        validValues: [Double] = [],
        validValuesRange: Range<Double>? = nil
    ) -> GenericCharacteristic<Enums.CurrentAirQuality> {
        return GenericCharacteristic<Enums.CurrentAirQuality>(
            type: .currentAirQuality,
            value: value,
            permissions: permissions,
            description: description,
            format: format,
            unit: unit,
            maxLength: maxLength,
            maxValue: maxValue,
            minValue: minValue,
            minStep: minStep,
            validValues: validValues,
            validValuesRange: validValuesRange)
    }

    static func currentDoorState(
        _ value: Enums.CurrentDoorState = .open,
        permissions: [CharacteristicPermission] = [.read, .events],
        description: String? = "Current Door State",
        format: CharacteristicFormat? = .uint8,
        unit: CharacteristicUnit? = nil,
        maxLength: Int? = nil,
        maxValue: Double? = 4,
        minValue: Double? = 0,
        minStep: Double? = 1,
        validValues: [Double] = [],
        validValuesRange: Range<Double>? = nil
    ) -> GenericCharacteristic<Enums.CurrentDoorState> {
        return GenericCharacteristic<Enums.CurrentDoorState>(
            type: .currentDoorState,
            value: value,
            permissions: permissions,
            description: description,
            format: format,
            unit: unit,
            maxLength: maxLength,
            maxValue: maxValue,
            minValue: minValue,
            minStep: minStep,
            validValues: validValues,
            validValuesRange: validValuesRange)
    }

    static func currentFanState(
        _ value: Enums.CurrentFanState = .inactive,
        permissions: [CharacteristicPermission] = [.read, .events],
        description: String? = "Current Fan State",
        format: CharacteristicFormat? = .uint8,
        unit: CharacteristicUnit? = nil,
        maxLength: Int? = nil,
        maxValue: Double? = 2,
        minValue: Double? = 0,
        minStep: Double? = 1,
        validValues: [Double] = [],
        validValuesRange: Range<Double>? = nil
    ) -> GenericCharacteristic<Enums.CurrentFanState> {
        return GenericCharacteristic<Enums.CurrentFanState>(
            type: .currentFanState,
            value: value,
            permissions: permissions,
            description: description,
            format: format,
            unit: unit,
            maxLength: maxLength,
            maxValue: maxValue,
            minValue: minValue,
            minStep: minStep,
            validValues: validValues,
            validValuesRange: validValuesRange)
    }

    static func currentHeaterCoolerState(
        _ value: Enums.CurrentHeaterCoolerState = .heating,
        permissions: [CharacteristicPermission] = [.read, .events],
        description: String? = "Current Heater-Cooler State",
        format: CharacteristicFormat? = .uint8,
        unit: CharacteristicUnit? = nil,
        maxLength: Int? = nil,
        maxValue: Double? = 3,
        minValue: Double? = 0,
        minStep: Double? = 1,
        validValues: [Double] = [],
        validValuesRange: Range<Double>? = nil
    ) -> GenericCharacteristic<Enums.CurrentHeaterCoolerState> {
        return GenericCharacteristic<Enums.CurrentHeaterCoolerState>(
            type: .currentHeaterCoolerState,
            value: value,
            permissions: permissions,
            description: description,
            format: format,
            unit: unit,
            maxLength: maxLength,
            maxValue: maxValue,
            minValue: minValue,
            minStep: minStep,
            validValues: validValues,
            validValuesRange: validValuesRange)
    }

    static func currentHeatingCoolingState(
        _ value: Enums.CurrentHeatingCoolingState = .cool,
        permissions: [CharacteristicPermission] = [.read, .events],
        description: String? = "Current Heating Cooling State",
        format: CharacteristicFormat? = .uint8,
        unit: CharacteristicUnit? = nil,
        maxLength: Int? = nil,
        maxValue: Double? = 2,
        minValue: Double? = 0,
        minStep: Double? = 1,
        validValues: [Double] = [],
        validValuesRange: Range<Double>? = nil
    ) -> GenericCharacteristic<Enums.CurrentHeatingCoolingState> {
        return GenericCharacteristic<Enums.CurrentHeatingCoolingState>(
            type: .currentHeatingCoolingState,
            value: value,
            permissions: permissions,
            description: description,
            format: format,
            unit: unit,
            maxLength: maxLength,
            maxValue: maxValue,
            minValue: minValue,
            minStep: minStep,
            validValues: validValues,
            validValuesRange: validValuesRange)
    }

    static func currentHorizontalTiltAngle(
        _ value: Int = -90,
        permissions: [CharacteristicPermission] = [.read, .events],
        description: String? = "Current Horizontal Tilt Angle",
        format: CharacteristicFormat? = .int,
        unit: CharacteristicUnit? = .arcdegrees,
        maxLength: Int? = nil,
        maxValue: Double? = 90,
        minValue: Double? = -90,
        minStep: Double? = 1,
        validValues: [Double] = [],
        validValuesRange: Range<Double>? = nil
    ) -> GenericCharacteristic<Int> {
        return GenericCharacteristic<Int>(
            type: .currentHorizontalTiltAngle,
            value: value,
            permissions: permissions,
            description: description,
            format: format,
            unit: unit,
            maxLength: maxLength,
            maxValue: maxValue,
            minValue: minValue,
            minStep: minStep,
            validValues: validValues,
            validValuesRange: validValuesRange)
    }

    static func currentHumidifierDehumidifierState(
        _ value: Enums.CurrentHumidifierDehumidifierState = .inactive,
        permissions: [CharacteristicPermission] = [.read, .events],
        description: String? = "Current Humidifier-Dehumidifier State",
        format: CharacteristicFormat? = .uint8,
        unit: CharacteristicUnit? = nil,
        maxLength: Int? = nil,
        maxValue: Double? = 3,
        minValue: Double? = 0,
        minStep: Double? = 1,
        validValues: [Double] = [],
        validValuesRange: Range<Double>? = nil
    ) -> GenericCharacteristic<Enums.CurrentHumidifierDehumidifierState> {
        return GenericCharacteristic<Enums.CurrentHumidifierDehumidifierState>(
            type: .currentHumidifierDehumidifierState,
            value: value,
            permissions: permissions,
            description: description,
            format: format,
            unit: unit,
            maxLength: maxLength,
            maxValue: maxValue,
            minValue: minValue,
            minStep: minStep,
            validValues: validValues,
            validValuesRange: validValuesRange)
    }

    static func currentLightLevel(
        _ value: Float = 0.0001,
        permissions: [CharacteristicPermission] = [.read, .events],
        description: String? = "Current Light Level",
        format: CharacteristicFormat? = .float,
        unit: CharacteristicUnit? = .lux,
        maxLength: Int? = nil,
        maxValue: Double? = 100000,
        minValue: Double? = 0.0001,
        minStep: Double? = nil,
        validValues: [Double] = [],
        validValuesRange: Range<Double>? = nil
    ) -> GenericCharacteristic<Float> {
        return GenericCharacteristic<Float>(
            type: .currentLightLevel,
            value: value,
            permissions: permissions,
            description: description,
            format: format,
            unit: unit,
            maxLength: maxLength,
            maxValue: maxValue,
            minValue: minValue,
            minStep: minStep,
            validValues: validValues,
            validValuesRange: validValuesRange)
    }

    static func currentMediaState(
        _ value: UInt8 = 0,
        permissions: [CharacteristicPermission] = [.read, .events],
        description: String? = "Current Media State",
        format: CharacteristicFormat? = .uint8,
        unit: CharacteristicUnit? = nil,
        maxLength: Int? = nil,
        maxValue: Double? = 5,
        minValue: Double? = 0,
        minStep: Double? = 1,
        validValues: [Double] = [],
        validValuesRange: Range<Double>? = nil
    ) -> GenericCharacteristic<UInt8> {
        return GenericCharacteristic<UInt8>(
            type: .currentMediaState,
            value: value,
            permissions: permissions,
            description: description,
            format: format,
            unit: unit,
            maxLength: maxLength,
            maxValue: maxValue,
            minValue: minValue,
            minStep: minStep,
            validValues: validValues,
            validValuesRange: validValuesRange)
    }

    static func currentPosition(
        _ value: UInt8 = 0,
        permissions: [CharacteristicPermission] = [.read, .events],
        description: String? = "Current Position",
        format: CharacteristicFormat? = .uint8,
        unit: CharacteristicUnit? = .percentage,
        maxLength: Int? = nil,
        maxValue: Double? = 100,
        minValue: Double? = 0,
        minStep: Double? = 1,
        validValues: [Double] = [],
        validValuesRange: Range<Double>? = nil
    ) -> GenericCharacteristic<UInt8> {
        return GenericCharacteristic<UInt8>(
            type: .currentPosition,
            value: value,
            permissions: permissions,
            description: description,
            format: format,
            unit: unit,
            maxLength: maxLength,
            maxValue: maxValue,
            minValue: minValue,
            minStep: minStep,
            validValues: validValues,
            validValuesRange: validValuesRange)
    }

    static func currentRelativeHumidity(
        _ value: Float = 0,
        permissions: [CharacteristicPermission] = [.read, .events],
        description: String? = "Current Relative Humidity",
        format: CharacteristicFormat? = .float,
        unit: CharacteristicUnit? = .percentage,
        maxLength: Int? = nil,
        maxValue: Double? = 100,
        minValue: Double? = 0,
        minStep: Double? = 1,
        validValues: [Double] = [],
        validValuesRange: Range<Double>? = nil
    ) -> GenericCharacteristic<Float> {
        return GenericCharacteristic<Float>(
            type: .currentRelativeHumidity,
            value: value,
            permissions: permissions,
            description: description,
            format: format,
            unit: unit,
            maxLength: maxLength,
            maxValue: maxValue,
            minValue: minValue,
            minStep: minStep,
            validValues: validValues,
            validValuesRange: validValuesRange)
    }

    static func currentSlatState(
        _ value: Enums.CurrentSlatState = .inactive,
        permissions: [CharacteristicPermission] = [.read, .events],
        description: String? = "Current Slat State",
        format: CharacteristicFormat? = .uint8,
        unit: CharacteristicUnit? = nil,
        maxLength: Int? = nil,
        maxValue: Double? = 3,
        minValue: Double? = 0,
        minStep: Double? = 1,
        validValues: [Double] = [],
        validValuesRange: Range<Double>? = nil
    ) -> GenericCharacteristic<Enums.CurrentSlatState> {
        return GenericCharacteristic<Enums.CurrentSlatState>(
            type: .currentSlatState,
            value: value,
            permissions: permissions,
            description: description,
            format: format,
            unit: unit,
            maxLength: maxLength,
            maxValue: maxValue,
            minValue: minValue,
            minStep: minStep,
            validValues: validValues,
            validValuesRange: validValuesRange)
    }

    static func currentTemperature(
        _ value: Float = 0,
        permissions: [CharacteristicPermission] = [.read, .events],
        description: String? = "Current Temperature",
        format: CharacteristicFormat? = .float,
        unit: CharacteristicUnit? = .celsius,
        maxLength: Int? = nil,
        maxValue: Double? = 100,
        minValue: Double? = 0,
        minStep: Double? = 0.1,
        validValues: [Double] = [],
        validValuesRange: Range<Double>? = nil
    ) -> GenericCharacteristic<Float> {
        return GenericCharacteristic<Float>(
            type: .currentTemperature,
            value: value,
            permissions: permissions,
            description: description,
            format: format,
            unit: unit,
            maxLength: maxLength,
            maxValue: maxValue,
            minValue: minValue,
            minStep: minStep,
            validValues: validValues,
            validValuesRange: validValuesRange)
    }

    static func currentTiltAngle(
        _ value: Int = -90,
        permissions: [CharacteristicPermission] = [.read, .events],
        description: String? = "Current Tilt Angle",
        format: CharacteristicFormat? = .int,
        unit: CharacteristicUnit? = .arcdegrees,
        maxLength: Int? = nil,
        maxValue: Double? = 90,
        minValue: Double? = -90,
        minStep: Double? = 1,
        validValues: [Double] = [],
        validValuesRange: Range<Double>? = nil
    ) -> GenericCharacteristic<Int> {
        return GenericCharacteristic<Int>(
            type: .currentTiltAngle,
            value: value,
            permissions: permissions,
            description: description,
            format: format,
            unit: unit,
            maxLength: maxLength,
            maxValue: maxValue,
            minValue: minValue,
            minStep: minStep,
            validValues: validValues,
            validValuesRange: validValuesRange)
    }

    static func currentTransport(
        _ value: Bool = false,
        permissions: [CharacteristicPermission] = [.read],
        description: String? = "Current Transport",
        format: CharacteristicFormat? = .bool,
        unit: CharacteristicUnit? = nil,
        maxLength: Int? = nil,
        maxValue: Double? = nil,
        minValue: Double? = nil,
        minStep: Double? = nil,
        validValues: [Double] = [],
        validValuesRange: Range<Double>? = nil
    ) -> GenericCharacteristic<Bool> {
        return GenericCharacteristic<Bool>(
            type: .currentTransport,
            value: value,
            permissions: permissions,
            description: description,
            format: format,
            unit: unit,
            maxLength: maxLength,
            maxValue: maxValue,
            minValue: minValue,
            minStep: minStep,
            validValues: validValues,
            validValuesRange: validValuesRange)
    }

    static func currentVerticalTiltAngle(
        _ value: Int = -90,
        permissions: [CharacteristicPermission] = [.read, .events],
        description: String? = "Current Vertical Tilt Angle",
        format: CharacteristicFormat? = .int,
        unit: CharacteristicUnit? = .arcdegrees,
        maxLength: Int? = nil,
        maxValue: Double? = 90,
        minValue: Double? = -90,
        minStep: Double? = 1,
        validValues: [Double] = [],
        validValuesRange: Range<Double>? = nil
    ) -> GenericCharacteristic<Int> {
        return GenericCharacteristic<Int>(
            type: .currentVerticalTiltAngle,
            value: value,
            permissions: permissions,
            description: description,
            format: format,
            unit: unit,
            maxLength: maxLength,
            maxValue: maxValue,
            minValue: minValue,
            minStep: minStep,
            validValues: validValues,
            validValuesRange: validValuesRange)
    }

    static func currentVisibilityState(
        _ value: Enums.CurrentVisibilityState = .shown,
        permissions: [CharacteristicPermission] = [.read, .events],
        description: String? = "Current Visibility State",
        format: CharacteristicFormat? = .uint8,
        unit: CharacteristicUnit? = nil,
        maxLength: Int? = nil,
        maxValue: Double? = 3,
        minValue: Double? = 0,
        minStep: Double? = 1,
        validValues: [Double] = [],
        validValuesRange: Range<Double>? = nil
    ) -> GenericCharacteristic<Enums.CurrentVisibilityState> {
        return GenericCharacteristic<Enums.CurrentVisibilityState>(
            type: .currentVisibilityState,
            value: value,
            permissions: permissions,
            description: description,
            format: format,
            unit: unit,
            maxLength: maxLength,
            maxValue: maxValue,
            minValue: minValue,
            minStep: minStep,
            validValues: validValues,
            validValuesRange: validValuesRange)
    }

    static func currentWaterLevel(
        _ value: Float = 0,
        permissions: [CharacteristicPermission] = [.read, .events],
        description: String? = "Current Water Level",
        format: CharacteristicFormat? = .float,
        unit: CharacteristicUnit? = .percentage,
        maxLength: Int? = nil,
        maxValue: Double? = 100,
        minValue: Double? = 0,
        minStep: Double? = 1,
        validValues: [Double] = [],
        validValuesRange: Range<Double>? = nil
    ) -> GenericCharacteristic<Float> {
        return GenericCharacteristic<Float>(
            type: .currentWaterLevel,
            value: value,
            permissions: permissions,
            description: description,
            format: format,
            unit: unit,
            maxLength: maxLength,
            maxValue: maxValue,
            minValue: minValue,
            minStep: minStep,
            validValues: validValues,
            validValuesRange: validValuesRange)
    }

    static func displayOrder(
        _ value: Data = Data(),
        permissions: [CharacteristicPermission] = [.read, .events],
        description: String? = "Display Order",
        format: CharacteristicFormat? = .tlv8,
        unit: CharacteristicUnit? = nil,
        maxLength: Int? = nil,
        maxValue: Double? = nil,
        minValue: Double? = nil,
        minStep: Double? = nil,
        validValues: [Double] = [],
        validValuesRange: Range<Double>? = nil
    ) -> GenericCharacteristic<Data> {
        return GenericCharacteristic<Data>(
            type: .displayOrder,
            value: value,
            permissions: permissions,
            description: description,
            format: format,
            unit: unit,
            maxLength: maxLength,
            maxValue: maxValue,
            minValue: minValue,
            minStep: minStep,
            validValues: validValues,
            validValuesRange: validValuesRange)
    }

    static func eventRetransmissionMaximum(
        _ value: UInt8 = 0,
        permissions: [CharacteristicPermission] = [.read],
        description: String? = "Event Retransmission Maximum",
        format: CharacteristicFormat? = .uint8,
        unit: CharacteristicUnit? = nil,
        maxLength: Int? = nil,
        maxValue: Double? = nil,
        minValue: Double? = nil,
        minStep: Double? = nil,
        validValues: [Double] = [],
        validValuesRange: Range<Double>? = nil
    ) -> GenericCharacteristic<UInt8> {
        return GenericCharacteristic<UInt8>(
            type: .eventRetransmissionMaximum,
            value: value,
            permissions: permissions,
            description: description,
            format: format,
            unit: unit,
            maxLength: maxLength,
            maxValue: maxValue,
            minValue: minValue,
            minStep: minStep,
            validValues: validValues,
            validValuesRange: validValuesRange)
    }

    static func eventTransmissionCounters(
        _ value: UInt32 = 0,
        permissions: [CharacteristicPermission] = [.read],
        description: String? = "Event Transmission Counters",
        format: CharacteristicFormat? = .uint32,
        unit: CharacteristicUnit? = nil,
        maxLength: Int? = nil,
        maxValue: Double? = nil,
        minValue: Double? = nil,
        minStep: Double? = nil,
        validValues: [Double] = [],
        validValuesRange: Range<Double>? = nil
    ) -> GenericCharacteristic<UInt32> {
        return GenericCharacteristic<UInt32>(
            type: .eventTransmissionCounters,
            value: value,
            permissions: permissions,
            description: description,
            format: format,
            unit: unit,
            maxLength: maxLength,
            maxValue: maxValue,
            minValue: minValue,
            minStep: minStep,
            validValues: validValues,
            validValuesRange: validValuesRange)
    }

    static func filterChangeIndication(
        _ value: Enums.FilterChangeIndication = .noChange,
        permissions: [CharacteristicPermission] = [.read, .events],
        description: String? = "Filter Change indication",
        format: CharacteristicFormat? = .uint8,
        unit: CharacteristicUnit? = nil,
        maxLength: Int? = nil,
        maxValue: Double? = 1,
        minValue: Double? = 0,
        minStep: Double? = 1,
        validValues: [Double] = [],
        validValuesRange: Range<Double>? = nil
    ) -> GenericCharacteristic<Enums.FilterChangeIndication> {
        return GenericCharacteristic<Enums.FilterChangeIndication>(
            type: .filterChangeIndication,
            value: value,
            permissions: permissions,
            description: description,
            format: format,
            unit: unit,
            maxLength: maxLength,
            maxValue: maxValue,
            minValue: minValue,
            minStep: minStep,
            validValues: validValues,
            validValuesRange: validValuesRange)
    }

    static func filterLifeLevel(
        _ value: Float = 0,
        permissions: [CharacteristicPermission] = [.read, .events],
        description: String? = "Filter Life Level",
        format: CharacteristicFormat? = .float,
        unit: CharacteristicUnit? = nil,
        maxLength: Int? = nil,
        maxValue: Double? = 100,
        minValue: Double? = 0,
        minStep: Double? = 1,
        validValues: [Double] = [],
        validValuesRange: Range<Double>? = nil
    ) -> GenericCharacteristic<Float> {
        return GenericCharacteristic<Float>(
            type: .filterLifeLevel,
            value: value,
            permissions: permissions,
            description: description,
            format: format,
            unit: unit,
            maxLength: maxLength,
            maxValue: maxValue,
            minValue: minValue,
            minStep: minStep,
            validValues: validValues,
            validValuesRange: validValuesRange)
    }

    static func filterResetChangeIndication(
        _ value: UInt8? = nil,
        permissions: [CharacteristicPermission] = [.write],
        description: String? = "Filter Reset Change Indication",
        format: CharacteristicFormat? = .uint8,
        unit: CharacteristicUnit? = nil,
        maxLength: Int? = nil,
        maxValue: Double? = 1,
        minValue: Double? = 1,
        minStep: Double? = 1,
        validValues: [Double] = [],
        validValuesRange: Range<Double>? = nil
    ) -> GenericCharacteristic<UInt8?> {
        return GenericCharacteristic<UInt8?>(
            type: .filterResetChangeIndication,
            value: value,
            permissions: permissions,
            description: description,
            format: format,
            unit: unit,
            maxLength: maxLength,
            maxValue: maxValue,
            minValue: minValue,
            minStep: minStep,
            validValues: validValues,
            validValuesRange: validValuesRange)
    }

    static func firmwareRevision(
        _ value: String = "",
        permissions: [CharacteristicPermission] = [.read],
        description: String? = "Firmware Revision",
        format: CharacteristicFormat? = .string,
        unit: CharacteristicUnit? = nil,
        maxLength: Int? = nil,
        maxValue: Double? = nil,
        minValue: Double? = nil,
        minStep: Double? = nil,
        validValues: [Double] = [],
        validValuesRange: Range<Double>? = nil
    ) -> GenericCharacteristic<String> {
        return GenericCharacteristic<String>(
            type: .firmwareRevision,
            value: value,
            permissions: permissions,
            description: description,
            format: format,
            unit: unit,
            maxLength: maxLength,
            maxValue: maxValue,
            minValue: minValue,
            minStep: minStep,
            validValues: validValues,
            validValuesRange: validValuesRange)
    }

    static func hardwareRevision(
        _ value: String = "",
        permissions: [CharacteristicPermission] = [.read],
        description: String? = "Hardware Revision",
        format: CharacteristicFormat? = .string,
        unit: CharacteristicUnit? = nil,
        maxLength: Int? = nil,
        maxValue: Double? = nil,
        minValue: Double? = nil,
        minStep: Double? = nil,
        validValues: [Double] = [],
        validValuesRange: Range<Double>? = nil
    ) -> GenericCharacteristic<String> {
        return GenericCharacteristic<String>(
            type: .hardwareRevision,
            value: value,
            permissions: permissions,
            description: description,
            format: format,
            unit: unit,
            maxLength: maxLength,
            maxValue: maxValue,
            minValue: minValue,
            minStep: minStep,
            validValues: validValues,
            validValuesRange: validValuesRange)
    }

    static func heartBeat(
        _ value: UInt32 = 0,
        permissions: [CharacteristicPermission] = [.read, .events],
        description: String? = "Heart Beat",
        format: CharacteristicFormat? = .uint32,
        unit: CharacteristicUnit? = nil,
        maxLength: Int? = nil,
        maxValue: Double? = nil,
        minValue: Double? = nil,
        minStep: Double? = nil,
        validValues: [Double] = [],
        validValuesRange: Range<Double>? = nil
    ) -> GenericCharacteristic<UInt32> {
        return GenericCharacteristic<UInt32>(
            type: .heartBeat,
            value: value,
            permissions: permissions,
            description: description,
            format: format,
            unit: unit,
            maxLength: maxLength,
            maxValue: maxValue,
            minValue: minValue,
            minStep: minStep,
            validValues: validValues,
            validValuesRange: validValuesRange)
    }

    static func heatingThresholdTemperature(
        _ value: Float = 0,
        permissions: [CharacteristicPermission] = [.read, .write, .events],
        description: String? = "Heating Threshold Temperature",
        format: CharacteristicFormat? = .float,
        unit: CharacteristicUnit? = .celsius,
        maxLength: Int? = nil,
        maxValue: Double? = 25,
        minValue: Double? = 0,
        minStep: Double? = 0.1,
        validValues: [Double] = [],
        validValuesRange: Range<Double>? = nil
    ) -> GenericCharacteristic<Float> {
        return GenericCharacteristic<Float>(
            type: .heatingThresholdTemperature,
            value: value,
            permissions: permissions,
            description: description,
            format: format,
            unit: unit,
            maxLength: maxLength,
            maxValue: maxValue,
            minValue: minValue,
            minStep: minStep,
            validValues: validValues,
            validValuesRange: validValuesRange)
    }

    static func holdPosition(
        _ value: Bool? = nil,
        permissions: [CharacteristicPermission] = [.write],
        description: String? = "Hold Position",
        format: CharacteristicFormat? = .bool,
        unit: CharacteristicUnit? = nil,
        maxLength: Int? = nil,
        maxValue: Double? = nil,
        minValue: Double? = nil,
        minStep: Double? = nil,
        validValues: [Double] = [],
        validValuesRange: Range<Double>? = nil
    ) -> GenericCharacteristic<Bool?> {
        return GenericCharacteristic<Bool?>(
            type: .holdPosition,
            value: value,
            permissions: permissions,
            description: description,
            format: format,
            unit: unit,
            maxLength: maxLength,
            maxValue: maxValue,
            minValue: minValue,
            minStep: minStep,
            validValues: validValues,
            validValuesRange: validValuesRange)
    }

    static func hue(
        _ value: Float = 0,
        permissions: [CharacteristicPermission] = [.read, .write, .events],
        description: String? = "Hue",
        format: CharacteristicFormat? = .float,
        unit: CharacteristicUnit? = .arcdegrees,
        maxLength: Int? = nil,
        maxValue: Double? = 360,
        minValue: Double? = 0,
        minStep: Double? = 1,
        validValues: [Double] = [],
        validValuesRange: Range<Double>? = nil
    ) -> GenericCharacteristic<Float> {
        return GenericCharacteristic<Float>(
            type: .hue,
            value: value,
            permissions: permissions,
            description: description,
            format: format,
            unit: unit,
            maxLength: maxLength,
            maxValue: maxValue,
            minValue: minValue,
            minStep: minStep,
            validValues: validValues,
            validValuesRange: validValuesRange)
    }

    static func identifier(
        _ value: UInt32 = 0,
        permissions: [CharacteristicPermission] = [.read],
        description: String? = "Identifier",
        format: CharacteristicFormat? = .uint32,
        unit: CharacteristicUnit? = nil,
        maxLength: Int? = nil,
        maxValue: Double? = nil,
        minValue: Double? = 0,
        minStep: Double? = nil,
        validValues: [Double] = [],
        validValuesRange: Range<Double>? = nil
    ) -> GenericCharacteristic<UInt32> {
        return GenericCharacteristic<UInt32>(
            type: .identifier,
            value: value,
            permissions: permissions,
            description: description,
            format: format,
            unit: unit,
            maxLength: maxLength,
            maxValue: maxValue,
            minValue: minValue,
            minStep: minStep,
            validValues: validValues,
            validValuesRange: validValuesRange)
    }

    static func identify(
        _ value: Bool? = nil,
        permissions: [CharacteristicPermission] = [.write],
        description: String? = "Identify",
        format: CharacteristicFormat? = .bool,
        unit: CharacteristicUnit? = nil,
        maxLength: Int? = nil,
        maxValue: Double? = nil,
        minValue: Double? = nil,
        minStep: Double? = nil,
        validValues: [Double] = [],
        validValuesRange: Range<Double>? = nil
    ) -> GenericCharacteristic<Bool?> {
        return GenericCharacteristic<Bool?>(
            type: .identify,
            value: value,
            permissions: permissions,
            description: description,
            format: format,
            unit: unit,
            maxLength: maxLength,
            maxValue: maxValue,
            minValue: minValue,
            minStep: minStep,
            validValues: validValues,
            validValuesRange: validValuesRange)
    }

    static func inUse(
        _ value: UInt8 = 0,
        permissions: [CharacteristicPermission] = [.read, .events],
        description: String? = "In Use",
        format: CharacteristicFormat? = .uint8,
        unit: CharacteristicUnit? = nil,
        maxLength: Int? = nil,
        maxValue: Double? = 1,
        minValue: Double? = 0,
        minStep: Double? = 1,
        validValues: [Double] = [],
        validValuesRange: Range<Double>? = nil
    ) -> GenericCharacteristic<UInt8> {
        return GenericCharacteristic<UInt8>(
            type: .inUse,
            value: value,
            permissions: permissions,
            description: description,
            format: format,
            unit: unit,
            maxLength: maxLength,
            maxValue: maxValue,
            minValue: minValue,
            minStep: minStep,
            validValues: validValues,
            validValuesRange: validValuesRange)
    }

    static func inputDeviceType(
        _ value: Enums.InputDeviceType = .audiosystem,
        permissions: [CharacteristicPermission] = [.read, .events],
        description: String? = "Input Device Type",
        format: CharacteristicFormat? = .uint8,
        unit: CharacteristicUnit? = nil,
        maxLength: Int? = nil,
        maxValue: Double? = 6,
        minValue: Double? = 0,
        minStep: Double? = 1,
        validValues: [Double] = [],
        validValuesRange: Range<Double>? = nil
    ) -> GenericCharacteristic<Enums.InputDeviceType> {
        return GenericCharacteristic<Enums.InputDeviceType>(
            type: .inputDeviceType,
            value: value,
            permissions: permissions,
            description: description,
            format: format,
            unit: unit,
            maxLength: maxLength,
            maxValue: maxValue,
            minValue: minValue,
            minStep: minStep,
            validValues: validValues,
            validValuesRange: validValuesRange)
    }

    static func inputSourceType(
        _ value: Enums.InputSourceType = .svideo,
        permissions: [CharacteristicPermission] = [.read, .events],
        description: String? = "Input Source Type",
        format: CharacteristicFormat? = .uint8,
        unit: CharacteristicUnit? = nil,
        maxLength: Int? = nil,
        maxValue: Double? = 10,
        minValue: Double? = 0,
        minStep: Double? = 1,
        validValues: [Double] = [],
        validValuesRange: Range<Double>? = nil
    ) -> GenericCharacteristic<Enums.InputSourceType> {
        return GenericCharacteristic<Enums.InputSourceType>(
            type: .inputSourceType,
            value: value,
            permissions: permissions,
            description: description,
            format: format,
            unit: unit,
            maxLength: maxLength,
            maxValue: maxValue,
            minValue: minValue,
            minStep: minStep,
            validValues: validValues,
            validValuesRange: validValuesRange)
    }

    static func isConfigured(
        _ value: Enums.IsConfigured = .notconfigured,
        permissions: [CharacteristicPermission] = [.read, .events],
        description: String? = "Is Configured",
        format: CharacteristicFormat? = .uint8,
        unit: CharacteristicUnit? = nil,
        maxLength: Int? = nil,
        maxValue: Double? = 1,
        minValue: Double? = 0,
        minStep: Double? = 1,
        validValues: [Double] = [],
        validValuesRange: Range<Double>? = nil
    ) -> GenericCharacteristic<Enums.IsConfigured> {
        return GenericCharacteristic<Enums.IsConfigured>(
            type: .isConfigured,
            value: value,
            permissions: permissions,
            description: description,
            format: format,
            unit: unit,
            maxLength: maxLength,
            maxValue: maxValue,
            minValue: minValue,
            minStep: minStep,
            validValues: validValues,
            validValuesRange: validValuesRange)
    }

    static func labelIndex(
        _ value: UInt8 = 1,
        permissions: [CharacteristicPermission] = [.read],
        description: String? = "Label Index",
        format: CharacteristicFormat? = .uint8,
        unit: CharacteristicUnit? = nil,
        maxLength: Int? = nil,
        maxValue: Double? = 255,
        minValue: Double? = 1,
        minStep: Double? = 1,
        validValues: [Double] = [],
        validValuesRange: Range<Double>? = nil
    ) -> GenericCharacteristic<UInt8> {
        return GenericCharacteristic<UInt8>(
            type: .labelIndex,
            value: value,
            permissions: permissions,
            description: description,
            format: format,
            unit: unit,
            maxLength: maxLength,
            maxValue: maxValue,
            minValue: minValue,
            minStep: minStep,
            validValues: validValues,
            validValuesRange: validValuesRange)
    }

    static func labelNamespace(
        _ value: UInt8 = 0,
        permissions: [CharacteristicPermission] = [.read],
        description: String? = "Label Namespace",
        format: CharacteristicFormat? = .uint8,
        unit: CharacteristicUnit? = nil,
        maxLength: Int? = nil,
        maxValue: Double? = 4,
        minValue: Double? = 0,
        minStep: Double? = 1,
        validValues: [Double] = [],
        validValuesRange: Range<Double>? = nil
    ) -> GenericCharacteristic<UInt8> {
        return GenericCharacteristic<UInt8>(
            type: .labelNamespace,
            value: value,
            permissions: permissions,
            description: description,
            format: format,
            unit: unit,
            maxLength: maxLength,
            maxValue: maxValue,
            minValue: minValue,
            minStep: minStep,
            validValues: validValues,
            validValuesRange: validValuesRange)
    }

    static func leakDetected(
        _ value: Enums.LeakDetected = .leakNotDetected,
        permissions: [CharacteristicPermission] = [.read, .events],
        description: String? = "Leak Detected",
        format: CharacteristicFormat? = .uint8,
        unit: CharacteristicUnit? = nil,
        maxLength: Int? = nil,
        maxValue: Double? = 1,
        minValue: Double? = 0,
        minStep: Double? = 1,
        validValues: [Double] = [],
        validValuesRange: Range<Double>? = nil
    ) -> GenericCharacteristic<Enums.LeakDetected> {
        return GenericCharacteristic<Enums.LeakDetected>(
            type: .leakDetected,
            value: value,
            permissions: permissions,
            description: description,
            format: format,
            unit: unit,
            maxLength: maxLength,
            maxValue: maxValue,
            minValue: minValue,
            minStep: minStep,
            validValues: validValues,
            validValuesRange: validValuesRange)
    }

    static func lockControlPoint(
        _ value: Data? = nil,
        permissions: [CharacteristicPermission] = [.write],
        description: String? = "Lock Control Point",
        format: CharacteristicFormat? = .tlv8,
        unit: CharacteristicUnit? = nil,
        maxLength: Int? = nil,
        maxValue: Double? = nil,
        minValue: Double? = nil,
        minStep: Double? = nil,
        validValues: [Double] = [],
        validValuesRange: Range<Double>? = nil
    ) -> GenericCharacteristic<Data?> {
        return GenericCharacteristic<Data?>(
            type: .lockControlPoint,
            value: value,
            permissions: permissions,
            description: description,
            format: format,
            unit: unit,
            maxLength: maxLength,
            maxValue: maxValue,
            minValue: minValue,
            minStep: minStep,
            validValues: validValues,
            validValuesRange: validValuesRange)
    }

    static func lockCurrentState(
        _ value: Enums.LockCurrentState = .unsecured,
        permissions: [CharacteristicPermission] = [.read, .events],
        description: String? = "Lock Current State",
        format: CharacteristicFormat? = .uint8,
        unit: CharacteristicUnit? = nil,
        maxLength: Int? = nil,
        maxValue: Double? = 3,
        minValue: Double? = 0,
        minStep: Double? = 1,
        validValues: [Double] = [],
        validValuesRange: Range<Double>? = nil
    ) -> GenericCharacteristic<Enums.LockCurrentState> {
        return GenericCharacteristic<Enums.LockCurrentState>(
            type: .lockCurrentState,
            value: value,
            permissions: permissions,
            description: description,
            format: format,
            unit: unit,
            maxLength: maxLength,
            maxValue: maxValue,
            minValue: minValue,
            minStep: minStep,
            validValues: validValues,
            validValuesRange: validValuesRange)
    }

    static func lockLastKnownAction(
        _ value: UInt8 = 0,
        permissions: [CharacteristicPermission] = [.read, .events],
        description: String? = "Lock Last Known Action",
        format: CharacteristicFormat? = .uint8,
        unit: CharacteristicUnit? = nil,
        maxLength: Int? = nil,
        maxValue: Double? = 8,
        minValue: Double? = 0,
        minStep: Double? = 1,
        validValues: [Double] = [],
        validValuesRange: Range<Double>? = nil
    ) -> GenericCharacteristic<UInt8> {
        return GenericCharacteristic<UInt8>(
            type: .lockLastKnownAction,
            value: value,
            permissions: permissions,
            description: description,
            format: format,
            unit: unit,
            maxLength: maxLength,
            maxValue: maxValue,
            minValue: minValue,
            minStep: minStep,
            validValues: validValues,
            validValuesRange: validValuesRange)
    }

    static func lockManagementAutoSecurityTimeout(
        _ value: UInt32 = 0,
        permissions: [CharacteristicPermission] = [.read, .write, .events],
        description: String? = "Lock Management Auto Security Timeout",
        format: CharacteristicFormat? = .uint32,
        unit: CharacteristicUnit? = .seconds,
        maxLength: Int? = nil,
        maxValue: Double? = nil,
        minValue: Double? = nil,
        minStep: Double? = nil,
        validValues: [Double] = [],
        validValuesRange: Range<Double>? = nil
    ) -> GenericCharacteristic<UInt32> {
        return GenericCharacteristic<UInt32>(
            type: .lockManagementAutoSecurityTimeout,
            value: value,
            permissions: permissions,
            description: description,
            format: format,
            unit: unit,
            maxLength: maxLength,
            maxValue: maxValue,
            minValue: minValue,
            minStep: minStep,
            validValues: validValues,
            validValuesRange: validValuesRange)
    }

    static func lockPhysicalControls(
        _ value: UInt8 = 0,
        permissions: [CharacteristicPermission] = [.read, .write, .events],
        description: String? = "Lock Physical Controls",
        format: CharacteristicFormat? = .uint8,
        unit: CharacteristicUnit? = nil,
        maxLength: Int? = nil,
        maxValue: Double? = 1,
        minValue: Double? = 0,
        minStep: Double? = 1,
        validValues: [Double] = [],
        validValuesRange: Range<Double>? = nil
    ) -> GenericCharacteristic<UInt8> {
        return GenericCharacteristic<UInt8>(
            type: .lockPhysicalControls,
            value: value,
            permissions: permissions,
            description: description,
            format: format,
            unit: unit,
            maxLength: maxLength,
            maxValue: maxValue,
            minValue: minValue,
            minStep: minStep,
            validValues: validValues,
            validValuesRange: validValuesRange)
    }

    static func lockTargetState(
        _ value: Enums.LockTargetState = .unsecured,
        permissions: [CharacteristicPermission] = [.read, .write, .events],
        description: String? = "Lock Target State",
        format: CharacteristicFormat? = .uint8,
        unit: CharacteristicUnit? = nil,
        maxLength: Int? = nil,
        maxValue: Double? = 1,
        minValue: Double? = 0,
        minStep: Double? = 1,
        validValues: [Double] = [],
        validValuesRange: Range<Double>? = nil
    ) -> GenericCharacteristic<Enums.LockTargetState> {
        return GenericCharacteristic<Enums.LockTargetState>(
            type: .lockTargetState,
            value: value,
            permissions: permissions,
            description: description,
            format: format,
            unit: unit,
            maxLength: maxLength,
            maxValue: maxValue,
            minValue: minValue,
            minStep: minStep,
            validValues: validValues,
            validValuesRange: validValuesRange)
    }

    static func logs(
        _ value: Data = Data(),
        permissions: [CharacteristicPermission] = [.read, .events],
        description: String? = "Logs",
        format: CharacteristicFormat? = .tlv8,
        unit: CharacteristicUnit? = nil,
        maxLength: Int? = nil,
        maxValue: Double? = nil,
        minValue: Double? = nil,
        minStep: Double? = nil,
        validValues: [Double] = [],
        validValuesRange: Range<Double>? = nil
    ) -> GenericCharacteristic<Data> {
        return GenericCharacteristic<Data>(
            type: .logs,
            value: value,
            permissions: permissions,
            description: description,
            format: format,
            unit: unit,
            maxLength: maxLength,
            maxValue: maxValue,
            minValue: minValue,
            minStep: minStep,
            validValues: validValues,
            validValuesRange: validValuesRange)
    }

    static func macRetransmissionMaximum(
        _ value: UInt8 = 0,
        permissions: [CharacteristicPermission] = [.read],
        description: String? = "MAC Retransmission Maximum",
        format: CharacteristicFormat? = .uint8,
        unit: CharacteristicUnit? = nil,
        maxLength: Int? = nil,
        maxValue: Double? = nil,
        minValue: Double? = nil,
        minStep: Double? = nil,
        validValues: [Double] = [],
        validValuesRange: Range<Double>? = nil
    ) -> GenericCharacteristic<UInt8> {
        return GenericCharacteristic<UInt8>(
            type: .macRetransmissionMaximum,
            value: value,
            permissions: permissions,
            description: description,
            format: format,
            unit: unit,
            maxLength: maxLength,
            maxValue: maxValue,
            minValue: minValue,
            minStep: minStep,
            validValues: validValues,
            validValuesRange: validValuesRange)
    }

    static func macTransmissionCounters(
        _ value: Data = Data(),
        permissions: [CharacteristicPermission] = [.read],
        description: String? = "MAC Transmission Counters",
        format: CharacteristicFormat? = .data,
        unit: CharacteristicUnit? = nil,
        maxLength: Int? = nil,
        maxValue: Double? = nil,
        minValue: Double? = nil,
        minStep: Double? = nil,
        validValues: [Double] = [],
        validValuesRange: Range<Double>? = nil
    ) -> GenericCharacteristic<Data> {
        return GenericCharacteristic<Data>(
            type: .macTransmissionCounters,
            value: value,
            permissions: permissions,
            description: description,
            format: format,
            unit: unit,
            maxLength: maxLength,
            maxValue: maxValue,
            minValue: minValue,
            minStep: minStep,
            validValues: validValues,
            validValuesRange: validValuesRange)
    }

    static func manufacturer(
        _ value: String = "",
        permissions: [CharacteristicPermission] = [.read],
        description: String? = "Manufacturer",
        format: CharacteristicFormat? = .string,
        unit: CharacteristicUnit? = nil,
        maxLength: Int? = nil,
        maxValue: Double? = nil,
        minValue: Double? = nil,
        minStep: Double? = nil,
        validValues: [Double] = [],
        validValuesRange: Range<Double>? = nil
    ) -> GenericCharacteristic<String> {
        return GenericCharacteristic<String>(
            type: .manufacturer,
            value: value,
            permissions: permissions,
            description: description,
            format: format,
            unit: unit,
            maxLength: maxLength,
            maxValue: maxValue,
            minValue: minValue,
            minStep: minStep,
            validValues: validValues,
            validValuesRange: validValuesRange)
    }

    static func maximumTransmitPower(
        _ value: Int = 0,
        permissions: [CharacteristicPermission] = [.read],
        description: String? = "Maximum Transmit Power",
        format: CharacteristicFormat? = .int,
        unit: CharacteristicUnit? = nil,
        maxLength: Int? = nil,
        maxValue: Double? = nil,
        minValue: Double? = nil,
        minStep: Double? = nil,
        validValues: [Double] = [],
        validValuesRange: Range<Double>? = nil
    ) -> GenericCharacteristic<Int> {
        return GenericCharacteristic<Int>(
            type: .maximumTransmitPower,
            value: value,
            permissions: permissions,
            description: description,
            format: format,
            unit: unit,
            maxLength: maxLength,
            maxValue: maxValue,
            minValue: minValue,
            minStep: minStep,
            validValues: validValues,
            validValuesRange: validValuesRange)
    }

    static func model(
        _ value: String = "",
        permissions: [CharacteristicPermission] = [.read],
        description: String? = "Model",
        format: CharacteristicFormat? = .string,
        unit: CharacteristicUnit? = nil,
        maxLength: Int? = nil,
        maxValue: Double? = nil,
        minValue: Double? = nil,
        minStep: Double? = nil,
        validValues: [Double] = [],
        validValuesRange: Range<Double>? = nil
    ) -> GenericCharacteristic<String> {
        return GenericCharacteristic<String>(
            type: .model,
            value: value,
            permissions: permissions,
            description: description,
            format: format,
            unit: unit,
            maxLength: maxLength,
            maxValue: maxValue,
            minValue: minValue,
            minStep: minStep,
            validValues: validValues,
            validValuesRange: validValuesRange)
    }

    static func motionDetected(
        _ value: Bool = false,
        permissions: [CharacteristicPermission] = [.read, .events],
        description: String? = "Motion Detected",
        format: CharacteristicFormat? = .bool,
        unit: CharacteristicUnit? = nil,
        maxLength: Int? = nil,
        maxValue: Double? = nil,
        minValue: Double? = nil,
        minStep: Double? = nil,
        validValues: [Double] = [],
        validValuesRange: Range<Double>? = nil
    ) -> GenericCharacteristic<Bool> {
        return GenericCharacteristic<Bool>(
            type: .motionDetected,
            value: value,
            permissions: permissions,
            description: description,
            format: format,
            unit: unit,
            maxLength: maxLength,
            maxValue: maxValue,
            minValue: minValue,
            minStep: minStep,
            validValues: validValues,
            validValuesRange: validValuesRange)
    }

    static func mute(
        _ value: Bool = false,
        permissions: [CharacteristicPermission] = [.read, .write, .events],
        description: String? = "Mute",
        format: CharacteristicFormat? = .bool,
        unit: CharacteristicUnit? = nil,
        maxLength: Int? = nil,
        maxValue: Double? = nil,
        minValue: Double? = nil,
        minStep: Double? = nil,
        validValues: [Double] = [],
        validValuesRange: Range<Double>? = nil
    ) -> GenericCharacteristic<Bool> {
        return GenericCharacteristic<Bool>(
            type: .mute,
            value: value,
            permissions: permissions,
            description: description,
            format: format,
            unit: unit,
            maxLength: maxLength,
            maxValue: maxValue,
            minValue: minValue,
            minStep: minStep,
            validValues: validValues,
            validValuesRange: validValuesRange)
    }

    static func name(
        _ value: String = "",
        permissions: [CharacteristicPermission] = [.read],
        description: String? = "Name",
        format: CharacteristicFormat? = .string,
        unit: CharacteristicUnit? = nil,
        maxLength: Int? = nil,
        maxValue: Double? = nil,
        minValue: Double? = nil,
        minStep: Double? = nil,
        validValues: [Double] = [],
        validValuesRange: Range<Double>? = nil
    ) -> GenericCharacteristic<String> {
        return GenericCharacteristic<String>(
            type: .name,
            value: value,
            permissions: permissions,
            description: description,
            format: format,
            unit: unit,
            maxLength: maxLength,
            maxValue: maxValue,
            minValue: minValue,
            minStep: minStep,
            validValues: validValues,
            validValuesRange: validValuesRange)
    }

    static func nitrogenDioxideDensity(
        _ value: Float = 0,
        permissions: [CharacteristicPermission] = [.read, .events],
        description: String? = "Nitrogen dioxide Density",
        format: CharacteristicFormat? = .float,
        unit: CharacteristicUnit? = .microgramsPerMCubed,
        maxLength: Int? = nil,
        maxValue: Double? = 1000,
        minValue: Double? = 0,
        minStep: Double? = 1,
        validValues: [Double] = [],
        validValuesRange: Range<Double>? = nil
    ) -> GenericCharacteristic<Float> {
        return GenericCharacteristic<Float>(
            type: .nitrogenDioxideDensity,
            value: value,
            permissions: permissions,
            description: description,
            format: format,
            unit: unit,
            maxLength: maxLength,
            maxValue: maxValue,
            minValue: minValue,
            minStep: minStep,
            validValues: validValues,
            validValuesRange: validValuesRange)
    }

    static func obstructionDetected(
        _ value: Bool = false,
        permissions: [CharacteristicPermission] = [.read, .events],
        description: String? = "Obstruction Detected",
        format: CharacteristicFormat? = .bool,
        unit: CharacteristicUnit? = nil,
        maxLength: Int? = nil,
        maxValue: Double? = nil,
        minValue: Double? = nil,
        minStep: Double? = nil,
        validValues: [Double] = [],
        validValuesRange: Range<Double>? = nil
    ) -> GenericCharacteristic<Bool> {
        return GenericCharacteristic<Bool>(
            type: .obstructionDetected,
            value: value,
            permissions: permissions,
            description: description,
            format: format,
            unit: unit,
            maxLength: maxLength,
            maxValue: maxValue,
            minValue: minValue,
            minStep: minStep,
            validValues: validValues,
            validValuesRange: validValuesRange)
    }

    static func occupancyDetected(
        _ value: Enums.OccupancyDetected = .occupancyDetected,
        permissions: [CharacteristicPermission] = [.read, .events],
        description: String? = "Occupancy Detected",
        format: CharacteristicFormat? = .uint8,
        unit: CharacteristicUnit? = nil,
        maxLength: Int? = nil,
        maxValue: Double? = 1,
        minValue: Double? = 0,
        minStep: Double? = 1,
        validValues: [Double] = [],
        validValuesRange: Range<Double>? = nil
    ) -> GenericCharacteristic<Enums.OccupancyDetected> {
        return GenericCharacteristic<Enums.OccupancyDetected>(
            type: .occupancyDetected,
            value: value,
            permissions: permissions,
            description: description,
            format: format,
            unit: unit,
            maxLength: maxLength,
            maxValue: maxValue,
            minValue: minValue,
            minStep: minStep,
            validValues: validValues,
            validValuesRange: validValuesRange)
    }

    static func operatingStateResponse(
        _ value: Data = Data(),
        permissions: [CharacteristicPermission] = [.read, .events],
        description: String? = "Operating State Response",
        format: CharacteristicFormat? = .tlv8,
        unit: CharacteristicUnit? = nil,
        maxLength: Int? = nil,
        maxValue: Double? = nil,
        minValue: Double? = nil,
        minStep: Double? = nil,
        validValues: [Double] = [],
        validValuesRange: Range<Double>? = nil
    ) -> GenericCharacteristic<Data> {
        return GenericCharacteristic<Data>(
            type: .operatingStateResponse,
            value: value,
            permissions: permissions,
            description: description,
            format: format,
            unit: unit,
            maxLength: maxLength,
            maxValue: maxValue,
            minValue: minValue,
            minStep: minStep,
            validValues: validValues,
            validValuesRange: validValuesRange)
    }

    static func outletInUse(
        _ value: Bool = false,
        permissions: [CharacteristicPermission] = [.read, .events],
        description: String? = "Outlet In Use",
        format: CharacteristicFormat? = .bool,
        unit: CharacteristicUnit? = nil,
        maxLength: Int? = nil,
        maxValue: Double? = nil,
        minValue: Double? = nil,
        minStep: Double? = nil,
        validValues: [Double] = [],
        validValuesRange: Range<Double>? = nil
    ) -> GenericCharacteristic<Bool> {
        return GenericCharacteristic<Bool>(
            type: .outletInUse,
            value: value,
            permissions: permissions,
            description: description,
            format: format,
            unit: unit,
            maxLength: maxLength,
            maxValue: maxValue,
            minValue: minValue,
            minStep: minStep,
            validValues: validValues,
            validValuesRange: validValuesRange)
    }

    static func ozoneDensity(
        _ value: Float = 0,
        permissions: [CharacteristicPermission] = [.read, .events],
        description: String? = "Ozone Density",
        format: CharacteristicFormat? = .float,
        unit: CharacteristicUnit? = .microgramsPerMCubed,
        maxLength: Int? = nil,
        maxValue: Double? = 1000,
        minValue: Double? = 0,
        minStep: Double? = 1,
        validValues: [Double] = [],
        validValuesRange: Range<Double>? = nil
    ) -> GenericCharacteristic<Float> {
        return GenericCharacteristic<Float>(
            type: .ozoneDensity,
            value: value,
            permissions: permissions,
            description: description,
            format: format,
            unit: unit,
            maxLength: maxLength,
            maxValue: maxValue,
            minValue: minValue,
            minStep: minStep,
            validValues: validValues,
            validValuesRange: validValuesRange)
    }

    static func pm10Density(
        _ value: Float = 0,
        permissions: [CharacteristicPermission] = [.read, .events],
        description: String? = "PM10 Density",
        format: CharacteristicFormat? = .float,
        unit: CharacteristicUnit? = .microgramsPerMCubed,
        maxLength: Int? = nil,
        maxValue: Double? = 1000,
        minValue: Double? = 0,
        minStep: Double? = 1,
        validValues: [Double] = [],
        validValuesRange: Range<Double>? = nil
    ) -> GenericCharacteristic<Float> {
        return GenericCharacteristic<Float>(
            type: .pm10Density,
            value: value,
            permissions: permissions,
            description: description,
            format: format,
            unit: unit,
            maxLength: maxLength,
            maxValue: maxValue,
            minValue: minValue,
            minStep: minStep,
            validValues: validValues,
            validValuesRange: validValuesRange)
    }

    static func pm2_5Density(
        _ value: Float = 0,
        permissions: [CharacteristicPermission] = [.read, .events],
        description: String? = "PM2.5 Density",
        format: CharacteristicFormat? = .float,
        unit: CharacteristicUnit? = .microgramsPerMCubed,
        maxLength: Int? = nil,
        maxValue: Double? = 1000,
        minValue: Double? = 0,
        minStep: Double? = 1,
        validValues: [Double] = [],
        validValuesRange: Range<Double>? = nil
    ) -> GenericCharacteristic<Float> {
        return GenericCharacteristic<Float>(
            type: .pm2_5Density,
            value: value,
            permissions: permissions,
            description: description,
            format: format,
            unit: unit,
            maxLength: maxLength,
            maxValue: maxValue,
            minValue: minValue,
            minStep: minStep,
            validValues: validValues,
            validValuesRange: validValuesRange)
    }

    static func pictureMode(
        _ value: Enums.PictureMode = .game,
        permissions: [CharacteristicPermission] = [.read, .write, .events],
        description: String? = "Picture Mode",
        format: CharacteristicFormat? = .uint8,
        unit: CharacteristicUnit? = nil,
        maxLength: Int? = nil,
        maxValue: Double? = 13,
        minValue: Double? = 0,
        minStep: Double? = 1,
        validValues: [Double] = [],
        validValuesRange: Range<Double>? = nil
    ) -> GenericCharacteristic<Enums.PictureMode> {
        return GenericCharacteristic<Enums.PictureMode>(
            type: .pictureMode,
            value: value,
            permissions: permissions,
            description: description,
            format: format,
            unit: unit,
            maxLength: maxLength,
            maxValue: maxValue,
            minValue: minValue,
            minStep: minStep,
            validValues: validValues,
            validValuesRange: validValuesRange)
    }

    static func ping(
        _ value: Data = Data(),
        permissions: [CharacteristicPermission] = [.read],
        description: String? = "Ping",
        format: CharacteristicFormat? = .data,
        unit: CharacteristicUnit? = nil,
        maxLength: Int? = nil,
        maxValue: Double? = nil,
        minValue: Double? = nil,
        minStep: Double? = nil,
        validValues: [Double] = [],
        validValuesRange: Range<Double>? = nil
    ) -> GenericCharacteristic<Data> {
        return GenericCharacteristic<Data>(
            type: .ping,
            value: value,
            permissions: permissions,
            description: description,
            format: format,
            unit: unit,
            maxLength: maxLength,
            maxValue: maxValue,
            minValue: minValue,
            minStep: minStep,
            validValues: validValues,
            validValuesRange: validValuesRange)
    }

    static func positionState(
        _ value: Enums.PositionState = .increasing,
        permissions: [CharacteristicPermission] = [.read, .events],
        description: String? = "Position State",
        format: CharacteristicFormat? = .uint8,
        unit: CharacteristicUnit? = nil,
        maxLength: Int? = nil,
        maxValue: Double? = 2,
        minValue: Double? = 0,
        minStep: Double? = 1,
        validValues: [Double] = [],
        validValuesRange: Range<Double>? = nil
    ) -> GenericCharacteristic<Enums.PositionState> {
        return GenericCharacteristic<Enums.PositionState>(
            type: .positionState,
            value: value,
            permissions: permissions,
            description: description,
            format: format,
            unit: unit,
            maxLength: maxLength,
            maxValue: maxValue,
            minValue: minValue,
            minStep: minStep,
            validValues: validValues,
            validValuesRange: validValuesRange)
    }

    static func powerModeSelection(
        _ value: Enums.PowerModeSelection? = nil,
        permissions: [CharacteristicPermission] = [.write],
        description: String? = "Power Mode Selection",
        format: CharacteristicFormat? = .uint8,
        unit: CharacteristicUnit? = nil,
        maxLength: Int? = nil,
        maxValue: Double? = 1,
        minValue: Double? = 0,
        minStep: Double? = 1,
        validValues: [Double] = [],
        validValuesRange: Range<Double>? = nil
    ) -> GenericCharacteristic<Enums.PowerModeSelection?> {
        return GenericCharacteristic<Enums.PowerModeSelection?>(
            type: .powerModeSelection,
            value: value,
            permissions: permissions,
            description: description,
            format: format,
            unit: unit,
            maxLength: maxLength,
            maxValue: maxValue,
            minValue: minValue,
            minStep: minStep,
            validValues: validValues,
            validValuesRange: validValuesRange)
    }

    static func powerState(
        _ value: Bool = false,
        permissions: [CharacteristicPermission] = [.read, .write, .events],
        description: String? = "Power State",
        format: CharacteristicFormat? = .bool,
        unit: CharacteristicUnit? = nil,
        maxLength: Int? = nil,
        maxValue: Double? = nil,
        minValue: Double? = nil,
        minStep: Double? = nil,
        validValues: [Double] = [],
        validValuesRange: Range<Double>? = nil
    ) -> GenericCharacteristic<Bool> {
        return GenericCharacteristic<Bool>(
            type: .powerState,
            value: value,
            permissions: permissions,
            description: description,
            format: format,
            unit: unit,
            maxLength: maxLength,
            maxValue: maxValue,
            minValue: minValue,
            minStep: minStep,
            validValues: validValues,
            validValuesRange: validValuesRange)
    }

    static func productData(
        _ value: Data = Data(),
        permissions: [CharacteristicPermission] = [.read],
        description: String? = "Product Data",
        format: CharacteristicFormat? = .data,
        unit: CharacteristicUnit? = nil,
        maxLength: Int? = nil,
        maxValue: Double? = nil,
        minValue: Double? = nil,
        minStep: Double? = nil,
        validValues: [Double] = [],
        validValuesRange: Range<Double>? = nil
    ) -> GenericCharacteristic<Data> {
        return GenericCharacteristic<Data>(
            type: .productData,
            value: value,
            permissions: permissions,
            description: description,
            format: format,
            unit: unit,
            maxLength: maxLength,
            maxValue: maxValue,
            minValue: minValue,
            minStep: minStep,
            validValues: validValues,
            validValuesRange: validValuesRange)
    }

    static func programMode(
        _ value: UInt8 = 0,
        permissions: [CharacteristicPermission] = [.read, .events],
        description: String? = "Program Mode",
        format: CharacteristicFormat? = .uint8,
        unit: CharacteristicUnit? = nil,
        maxLength: Int? = nil,
        maxValue: Double? = 2,
        minValue: Double? = 0,
        minStep: Double? = 1,
        validValues: [Double] = [],
        validValuesRange: Range<Double>? = nil
    ) -> GenericCharacteristic<UInt8> {
        return GenericCharacteristic<UInt8>(
            type: .programMode,
            value: value,
            permissions: permissions,
            description: description,
            format: format,
            unit: unit,
            maxLength: maxLength,
            maxValue: maxValue,
            minValue: minValue,
            minStep: minStep,
            validValues: validValues,
            validValuesRange: validValuesRange)
    }

    static func programmableSwitchEvent(
        _ value: UInt8 = 0,
        permissions: [CharacteristicPermission] = [.read, .events],
        description: String? = "Programmable Switch Event",
        format: CharacteristicFormat? = .uint8,
        unit: CharacteristicUnit? = nil,
        maxLength: Int? = nil,
        maxValue: Double? = 2,
        minValue: Double? = 0,
        minStep: Double? = 1,
        validValues: [Double] = [],
        validValuesRange: Range<Double>? = nil
    ) -> GenericCharacteristic<UInt8> {
        return GenericCharacteristic<UInt8>(
            type: .programmableSwitchEvent,
            value: value,
            permissions: permissions,
            description: description,
            format: format,
            unit: unit,
            maxLength: maxLength,
            maxValue: maxValue,
            minValue: minValue,
            minStep: minStep,
            validValues: validValues,
            validValuesRange: validValuesRange)
    }

    static func programmableSwitchOutputState(
        _ value: UInt8 = 0,
        permissions: [CharacteristicPermission] = [.read, .write, .events],
        description: String? = "Programmable Switch Output State",
        format: CharacteristicFormat? = .uint8,
        unit: CharacteristicUnit? = nil,
        maxLength: Int? = nil,
        maxValue: Double? = 1,
        minValue: Double? = 0,
        minStep: Double? = 1,
        validValues: [Double] = [],
        validValuesRange: Range<Double>? = nil
    ) -> GenericCharacteristic<UInt8> {
        return GenericCharacteristic<UInt8>(
            type: .programmableSwitchOutputState,
            value: value,
            permissions: permissions,
            description: description,
            format: format,
            unit: unit,
            maxLength: maxLength,
            maxValue: maxValue,
            minValue: minValue,
            minStep: minStep,
            validValues: validValues,
            validValuesRange: validValuesRange)
    }

    static func receivedSignalStrengthIndication(
        _ value: Int = 0,
        permissions: [CharacteristicPermission] = [.read],
        description: String? = "Received Signal Strength Indication",
        format: CharacteristicFormat? = .int,
        unit: CharacteristicUnit? = nil,
        maxLength: Int? = nil,
        maxValue: Double? = nil,
        minValue: Double? = nil,
        minStep: Double? = nil,
        validValues: [Double] = [],
        validValuesRange: Range<Double>? = nil
    ) -> GenericCharacteristic<Int> {
        return GenericCharacteristic<Int>(
            type: .receivedSignalStrengthIndication,
            value: value,
            permissions: permissions,
            description: description,
            format: format,
            unit: unit,
            maxLength: maxLength,
            maxValue: maxValue,
            minValue: minValue,
            minStep: minStep,
            validValues: validValues,
            validValuesRange: validValuesRange)
    }

    static func receiverSensitivity(
        _ value: Int = 0,
        permissions: [CharacteristicPermission] = [.read],
        description: String? = "Receiver Sensitivity",
        format: CharacteristicFormat? = .int,
        unit: CharacteristicUnit? = nil,
        maxLength: Int? = nil,
        maxValue: Double? = nil,
        minValue: Double? = nil,
        minStep: Double? = nil,
        validValues: [Double] = [],
        validValuesRange: Range<Double>? = nil
    ) -> GenericCharacteristic<Int> {
        return GenericCharacteristic<Int>(
            type: .receiverSensitivity,
            value: value,
            permissions: permissions,
            description: description,
            format: format,
            unit: unit,
            maxLength: maxLength,
            maxValue: maxValue,
            minValue: minValue,
            minStep: minStep,
            validValues: validValues,
            validValuesRange: validValuesRange)
    }

    static func relativeHumidityDehumidifierThreshold(
        _ value: Float = 0,
        permissions: [CharacteristicPermission] = [.read, .write, .events],
        description: String? = "Relative Humidity Dehumidifier Threshold",
        format: CharacteristicFormat? = .float,
        unit: CharacteristicUnit? = .percentage,
        maxLength: Int? = nil,
        maxValue: Double? = 100,
        minValue: Double? = 0,
        minStep: Double? = 1,
        validValues: [Double] = [],
        validValuesRange: Range<Double>? = nil
    ) -> GenericCharacteristic<Float> {
        return GenericCharacteristic<Float>(
            type: .relativeHumidityDehumidifierThreshold,
            value: value,
            permissions: permissions,
            description: description,
            format: format,
            unit: unit,
            maxLength: maxLength,
            maxValue: maxValue,
            minValue: minValue,
            minStep: minStep,
            validValues: validValues,
            validValuesRange: validValuesRange)
    }

    static func relativeHumidityHumidifierThreshold(
        _ value: Float = 0,
        permissions: [CharacteristicPermission] = [.read, .write, .events],
        description: String? = "Relative Humidity Humidifier Threshold",
        format: CharacteristicFormat? = .float,
        unit: CharacteristicUnit? = .percentage,
        maxLength: Int? = nil,
        maxValue: Double? = 100,
        minValue: Double? = 0,
        minStep: Double? = 1,
        validValues: [Double] = [],
        validValuesRange: Range<Double>? = nil
    ) -> GenericCharacteristic<Float> {
        return GenericCharacteristic<Float>(
            type: .relativeHumidityHumidifierThreshold,
            value: value,
            permissions: permissions,
            description: description,
            format: format,
            unit: unit,
            maxLength: maxLength,
            maxValue: maxValue,
            minValue: minValue,
            minStep: minStep,
            validValues: validValues,
            validValuesRange: validValuesRange)
    }

    static func remainingDuration(
        _ value: UInt32 = 0,
        permissions: [CharacteristicPermission] = [.read, .events],
        description: String? = "Remaining Duration",
        format: CharacteristicFormat? = .uint32,
        unit: CharacteristicUnit? = .seconds,
        maxLength: Int? = nil,
        maxValue: Double? = 3600,
        minValue: Double? = 0,
        minStep: Double? = 1,
        validValues: [Double] = [],
        validValuesRange: Range<Double>? = nil
    ) -> GenericCharacteristic<UInt32> {
        return GenericCharacteristic<UInt32>(
            type: .remainingDuration,
            value: value,
            permissions: permissions,
            description: description,
            format: format,
            unit: unit,
            maxLength: maxLength,
            maxValue: maxValue,
            minValue: minValue,
            minStep: minStep,
            validValues: validValues,
            validValuesRange: validValuesRange)
    }

    static func remoteKey(
        _ value: Enums.RemoteKey? = nil,
        permissions: [CharacteristicPermission] = [.write],
        description: String? = "Remote Key",
        format: CharacteristicFormat? = .uint8,
        unit: CharacteristicUnit? = nil,
        maxLength: Int? = nil,
        maxValue: Double? = 16,
        minValue: Double? = 0,
        minStep: Double? = 1,
        validValues: [Double] = [],
        validValuesRange: Range<Double>? = nil
    ) -> GenericCharacteristic<Enums.RemoteKey?> {
        return GenericCharacteristic<Enums.RemoteKey?>(
            type: .remoteKey,
            value: value,
            permissions: permissions,
            description: description,
            format: format,
            unit: unit,
            maxLength: maxLength,
            maxValue: maxValue,
            minValue: minValue,
            minStep: minStep,
            validValues: validValues,
            validValuesRange: validValuesRange)
    }

    static func rotationDirection(
        _ value: Enums.RotationDirection = .counterclockwise,
        permissions: [CharacteristicPermission] = [.read, .write, .events],
        description: String? = "Rotation Direction",
        format: CharacteristicFormat? = .int,
        unit: CharacteristicUnit? = nil,
        maxLength: Int? = nil,
        maxValue: Double? = 1,
        minValue: Double? = 0,
        minStep: Double? = 1,
        validValues: [Double] = [],
        validValuesRange: Range<Double>? = nil
    ) -> GenericCharacteristic<Enums.RotationDirection> {
        return GenericCharacteristic<Enums.RotationDirection>(
            type: .rotationDirection,
            value: value,
            permissions: permissions,
            description: description,
            format: format,
            unit: unit,
            maxLength: maxLength,
            maxValue: maxValue,
            minValue: minValue,
            minStep: minStep,
            validValues: validValues,
            validValuesRange: validValuesRange)
    }

    static func rotationSpeed(
        _ value: Float = 0,
        permissions: [CharacteristicPermission] = [.read, .write, .events],
        description: String? = "Rotation Speed",
        format: CharacteristicFormat? = .float,
        unit: CharacteristicUnit? = nil,
        maxLength: Int? = nil,
        maxValue: Double? = 100,
        minValue: Double? = 0,
        minStep: Double? = 1,
        validValues: [Double] = [],
        validValuesRange: Range<Double>? = nil
    ) -> GenericCharacteristic<Float> {
        return GenericCharacteristic<Float>(
            type: .rotationSpeed,
            value: value,
            permissions: permissions,
            description: description,
            format: format,
            unit: unit,
            maxLength: maxLength,
            maxValue: maxValue,
            minValue: minValue,
            minStep: minStep,
            validValues: validValues,
            validValuesRange: validValuesRange)
    }

    static func saturation(
        _ value: Float = 0,
        permissions: [CharacteristicPermission] = [.read, .write, .events],
        description: String? = "Saturation",
        format: CharacteristicFormat? = .float,
        unit: CharacteristicUnit? = .percentage,
        maxLength: Int? = nil,
        maxValue: Double? = 100,
        minValue: Double? = 0,
        minStep: Double? = 1,
        validValues: [Double] = [],
        validValuesRange: Range<Double>? = nil
    ) -> GenericCharacteristic<Float> {
        return GenericCharacteristic<Float>(
            type: .saturation,
            value: value,
            permissions: permissions,
            description: description,
            format: format,
            unit: unit,
            maxLength: maxLength,
            maxValue: maxValue,
            minValue: minValue,
            minStep: minStep,
            validValues: validValues,
            validValuesRange: validValuesRange)
    }

    static func securitySystemAlarmType(
        _ value: UInt8 = 0,
        permissions: [CharacteristicPermission] = [.read, .events],
        description: String? = "Security System Alarm Type",
        format: CharacteristicFormat? = .uint8,
        unit: CharacteristicUnit? = nil,
        maxLength: Int? = nil,
        maxValue: Double? = 1,
        minValue: Double? = 0,
        minStep: Double? = 1,
        validValues: [Double] = [],
        validValuesRange: Range<Double>? = nil
    ) -> GenericCharacteristic<UInt8> {
        return GenericCharacteristic<UInt8>(
            type: .securitySystemAlarmType,
            value: value,
            permissions: permissions,
            description: description,
            format: format,
            unit: unit,
            maxLength: maxLength,
            maxValue: maxValue,
            minValue: minValue,
            minStep: minStep,
            validValues: validValues,
            validValuesRange: validValuesRange)
    }

    static func securitySystemCurrentState(
        _ value: Enums.SecuritySystemCurrentState = .disarm,
        permissions: [CharacteristicPermission] = [.read, .events],
        description: String? = "Security System Current State",
        format: CharacteristicFormat? = .uint8,
        unit: CharacteristicUnit? = nil,
        maxLength: Int? = nil,
        maxValue: Double? = 4,
        minValue: Double? = 0,
        minStep: Double? = 1,
        validValues: [Double] = [],
        validValuesRange: Range<Double>? = nil
    ) -> GenericCharacteristic<Enums.SecuritySystemCurrentState> {
        return GenericCharacteristic<Enums.SecuritySystemCurrentState>(
            type: .securitySystemCurrentState,
            value: value,
            permissions: permissions,
            description: description,
            format: format,
            unit: unit,
            maxLength: maxLength,
            maxValue: maxValue,
            minValue: minValue,
            minStep: minStep,
            validValues: validValues,
            validValuesRange: validValuesRange)
    }

    static func securitySystemTargetState(
        _ value: Enums.SecuritySystemTargetState = .disarm,
        permissions: [CharacteristicPermission] = [.read, .write, .events],
        description: String? = "Security System Target State",
        format: CharacteristicFormat? = .uint8,
        unit: CharacteristicUnit? = nil,
        maxLength: Int? = nil,
        maxValue: Double? = 3,
        minValue: Double? = 0,
        minStep: Double? = 1,
        validValues: [Double] = [],
        validValuesRange: Range<Double>? = nil
    ) -> GenericCharacteristic<Enums.SecuritySystemTargetState> {
        return GenericCharacteristic<Enums.SecuritySystemTargetState>(
            type: .securitySystemTargetState,
            value: value,
            permissions: permissions,
            description: description,
            format: format,
            unit: unit,
            maxLength: maxLength,
            maxValue: maxValue,
            minValue: minValue,
            minStep: minStep,
            validValues: validValues,
            validValuesRange: validValuesRange)
    }

    static func serialNumber(
        _ value: String = "",
        permissions: [CharacteristicPermission] = [.read],
        description: String? = "Serial Number",
        format: CharacteristicFormat? = .string,
        unit: CharacteristicUnit? = nil,
        maxLength: Int? = nil,
        maxValue: Double? = nil,
        minValue: Double? = nil,
        minStep: Double? = nil,
        validValues: [Double] = [],
        validValuesRange: Range<Double>? = nil
    ) -> GenericCharacteristic<String> {
        return GenericCharacteristic<String>(
            type: .serialNumber,
            value: value,
            permissions: permissions,
            description: description,
            format: format,
            unit: unit,
            maxLength: maxLength,
            maxValue: maxValue,
            minValue: minValue,
            minStep: minStep,
            validValues: validValues,
            validValuesRange: validValuesRange)
    }

    static func setDuration(
        _ value: UInt32 = 0,
        permissions: [CharacteristicPermission] = [.read, .write, .events],
        description: String? = "Set Duration",
        format: CharacteristicFormat? = .uint32,
        unit: CharacteristicUnit? = .seconds,
        maxLength: Int? = nil,
        maxValue: Double? = 3600,
        minValue: Double? = 0,
        minStep: Double? = 1,
        validValues: [Double] = [],
        validValuesRange: Range<Double>? = nil
    ) -> GenericCharacteristic<UInt32> {
        return GenericCharacteristic<UInt32>(
            type: .setDuration,
            value: value,
            permissions: permissions,
            description: description,
            format: format,
            unit: unit,
            maxLength: maxLength,
            maxValue: maxValue,
            minValue: minValue,
            minStep: minStep,
            validValues: validValues,
            validValuesRange: validValuesRange)
    }

    static func setupTransferTransport(
        _ value: Data? = nil,
        permissions: [CharacteristicPermission] = [.write],
        description: String? = "Setup Transfer Transport",
        format: CharacteristicFormat? = .tlv8,
        unit: CharacteristicUnit? = nil,
        maxLength: Int? = nil,
        maxValue: Double? = nil,
        minValue: Double? = nil,
        minStep: Double? = nil,
        validValues: [Double] = [],
        validValuesRange: Range<Double>? = nil
    ) -> GenericCharacteristic<Data?> {
        return GenericCharacteristic<Data?>(
            type: .setupTransferTransport,
            value: value,
            permissions: permissions,
            description: description,
            format: format,
            unit: unit,
            maxLength: maxLength,
            maxValue: maxValue,
            minValue: minValue,
            minStep: minStep,
            validValues: validValues,
            validValuesRange: validValuesRange)
    }

    static func signalToNoiseRatio(
        _ value: Int = 0,
        permissions: [CharacteristicPermission] = [.read],
        description: String? = "Signal-to-noise Ratio",
        format: CharacteristicFormat? = .int,
        unit: CharacteristicUnit? = nil,
        maxLength: Int? = nil,
        maxValue: Double? = nil,
        minValue: Double? = nil,
        minStep: Double? = nil,
        validValues: [Double] = [],
        validValuesRange: Range<Double>? = nil
    ) -> GenericCharacteristic<Int> {
        return GenericCharacteristic<Int>(
            type: .signalToNoiseRatio,
            value: value,
            permissions: permissions,
            description: description,
            format: format,
            unit: unit,
            maxLength: maxLength,
            maxValue: maxValue,
            minValue: minValue,
            minStep: minStep,
            validValues: validValues,
            validValuesRange: validValuesRange)
    }

    static func slatType(
        _ value: UInt8 = 0,
        permissions: [CharacteristicPermission] = [.read],
        description: String? = "Slat Type",
        format: CharacteristicFormat? = .uint8,
        unit: CharacteristicUnit? = nil,
        maxLength: Int? = nil,
        maxValue: Double? = 1,
        minValue: Double? = 0,
        minStep: Double? = 1,
        validValues: [Double] = [],
        validValuesRange: Range<Double>? = nil
    ) -> GenericCharacteristic<UInt8> {
        return GenericCharacteristic<UInt8>(
            type: .slatType,
            value: value,
            permissions: permissions,
            description: description,
            format: format,
            unit: unit,
            maxLength: maxLength,
            maxValue: maxValue,
            minValue: minValue,
            minStep: minStep,
            validValues: validValues,
            validValuesRange: validValuesRange)
    }

    static func sleepDiscoveryMode(
        _ value: Enums.SleepDiscoveryMode = .notdiscoverable,
        permissions: [CharacteristicPermission] = [.read, .events],
        description: String? = "Sleep Discovery Mode",
        format: CharacteristicFormat? = .uint8,
        unit: CharacteristicUnit? = nil,
        maxLength: Int? = nil,
        maxValue: Double? = 1,
        minValue: Double? = 0,
        minStep: Double? = 1,
        validValues: [Double] = [],
        validValuesRange: Range<Double>? = nil
    ) -> GenericCharacteristic<Enums.SleepDiscoveryMode> {
        return GenericCharacteristic<Enums.SleepDiscoveryMode>(
            type: .sleepDiscoveryMode,
            value: value,
            permissions: permissions,
            description: description,
            format: format,
            unit: unit,
            maxLength: maxLength,
            maxValue: maxValue,
            minValue: minValue,
            minStep: minStep,
            validValues: validValues,
            validValuesRange: validValuesRange)
    }

    static func sleepInterval(
        _ value: UInt32 = 0,
        permissions: [CharacteristicPermission] = [.read, .events],
        description: String? = "Sleep Interval",
        format: CharacteristicFormat? = .uint32,
        unit: CharacteristicUnit? = nil,
        maxLength: Int? = nil,
        maxValue: Double? = nil,
        minValue: Double? = 0,
        minStep: Double? = 1,
        validValues: [Double] = [],
        validValuesRange: Range<Double>? = nil
    ) -> GenericCharacteristic<UInt32> {
        return GenericCharacteristic<UInt32>(
            type: .sleepInterval,
            value: value,
            permissions: permissions,
            description: description,
            format: format,
            unit: unit,
            maxLength: maxLength,
            maxValue: maxValue,
            minValue: minValue,
            minStep: minStep,
            validValues: validValues,
            validValuesRange: validValuesRange)
    }

    static func smokeDetected(
        _ value: Enums.SmokeDetected = .smokedetected,
        permissions: [CharacteristicPermission] = [.read, .events],
        description: String? = "Smoke Detected",
        format: CharacteristicFormat? = .uint8,
        unit: CharacteristicUnit? = nil,
        maxLength: Int? = nil,
        maxValue: Double? = 1,
        minValue: Double? = 0,
        minStep: Double? = 1,
        validValues: [Double] = [],
        validValuesRange: Range<Double>? = nil
    ) -> GenericCharacteristic<Enums.SmokeDetected> {
        return GenericCharacteristic<Enums.SmokeDetected>(
            type: .smokeDetected,
            value: value,
            permissions: permissions,
            description: description,
            format: format,
            unit: unit,
            maxLength: maxLength,
            maxValue: maxValue,
            minValue: minValue,
            minStep: minStep,
            validValues: validValues,
            validValuesRange: validValuesRange)
    }

    static func softwareRevision(
        _ value: String = "",
        permissions: [CharacteristicPermission] = [.read],
        description: String? = "Software Revision",
        format: CharacteristicFormat? = .string,
        unit: CharacteristicUnit? = nil,
        maxLength: Int? = nil,
        maxValue: Double? = nil,
        minValue: Double? = nil,
        minStep: Double? = nil,
        validValues: [Double] = [],
        validValuesRange: Range<Double>? = nil
    ) -> GenericCharacteristic<String> {
        return GenericCharacteristic<String>(
            type: .softwareRevision,
            value: value,
            permissions: permissions,
            description: description,
            format: format,
            unit: unit,
            maxLength: maxLength,
            maxValue: maxValue,
            minValue: minValue,
            minStep: minStep,
            validValues: validValues,
            validValuesRange: validValuesRange)
    }

    static func statusActive(
        _ value: Bool = false,
        permissions: [CharacteristicPermission] = [.read, .events],
        description: String? = "Status Active",
        format: CharacteristicFormat? = .bool,
        unit: CharacteristicUnit? = nil,
        maxLength: Int? = nil,
        maxValue: Double? = nil,
        minValue: Double? = nil,
        minStep: Double? = nil,
        validValues: [Double] = [],
        validValuesRange: Range<Double>? = nil
    ) -> GenericCharacteristic<Bool> {
        return GenericCharacteristic<Bool>(
            type: .statusActive,
            value: value,
            permissions: permissions,
            description: description,
            format: format,
            unit: unit,
            maxLength: maxLength,
            maxValue: maxValue,
            minValue: minValue,
            minStep: minStep,
            validValues: validValues,
            validValuesRange: validValuesRange)
    }

    static func statusFault(
        _ value: UInt8 = 0,
        permissions: [CharacteristicPermission] = [.read, .events],
        description: String? = "Status Fault",
        format: CharacteristicFormat? = .uint8,
        unit: CharacteristicUnit? = nil,
        maxLength: Int? = nil,
        maxValue: Double? = 1,
        minValue: Double? = 0,
        minStep: Double? = 1,
        validValues: [Double] = [],
        validValuesRange: Range<Double>? = nil
    ) -> GenericCharacteristic<UInt8> {
        return GenericCharacteristic<UInt8>(
            type: .statusFault,
            value: value,
            permissions: permissions,
            description: description,
            format: format,
            unit: unit,
            maxLength: maxLength,
            maxValue: maxValue,
            minValue: minValue,
            minStep: minStep,
            validValues: validValues,
            validValuesRange: validValuesRange)
    }

    static func statusLowBattery(
        _ value: Enums.StatusLowBattery = .batteryNormal,
        permissions: [CharacteristicPermission] = [.read, .events],
        description: String? = "Status Low Battery",
        format: CharacteristicFormat? = .uint8,
        unit: CharacteristicUnit? = nil,
        maxLength: Int? = nil,
        maxValue: Double? = 1,
        minValue: Double? = 0,
        minStep: Double? = 1,
        validValues: [Double] = [],
        validValuesRange: Range<Double>? = nil
    ) -> GenericCharacteristic<Enums.StatusLowBattery> {
        return GenericCharacteristic<Enums.StatusLowBattery>(
            type: .statusLowBattery,
            value: value,
            permissions: permissions,
            description: description,
            format: format,
            unit: unit,
            maxLength: maxLength,
            maxValue: maxValue,
            minValue: minValue,
            minStep: minStep,
            validValues: validValues,
            validValuesRange: validValuesRange)
    }

    static func statusTampered(
        _ value: UInt8 = 0,
        permissions: [CharacteristicPermission] = [.read, .events],
        description: String? = "Status Tampered",
        format: CharacteristicFormat? = .uint8,
        unit: CharacteristicUnit? = nil,
        maxLength: Int? = nil,
        maxValue: Double? = 1,
        minValue: Double? = 0,
        minStep: Double? = 1,
        validValues: [Double] = [],
        validValuesRange: Range<Double>? = nil
    ) -> GenericCharacteristic<UInt8> {
        return GenericCharacteristic<UInt8>(
            type: .statusTampered,
            value: value,
            permissions: permissions,
            description: description,
            format: format,
            unit: unit,
            maxLength: maxLength,
            maxValue: maxValue,
            minValue: minValue,
            minStep: minStep,
            validValues: validValues,
            validValuesRange: validValuesRange)
    }

    static func sulphurDioxideDensity(
        _ value: Float = 0,
        permissions: [CharacteristicPermission] = [.read, .events],
        description: String? = "Sulphur dioxide Density",
        format: CharacteristicFormat? = .float,
        unit: CharacteristicUnit? = .microgramsPerMCubed,
        maxLength: Int? = nil,
        maxValue: Double? = 1000,
        minValue: Double? = 0,
        minStep: Double? = 1,
        validValues: [Double] = [],
        validValuesRange: Range<Double>? = nil
    ) -> GenericCharacteristic<Float> {
        return GenericCharacteristic<Float>(
            type: .sulphurDioxideDensity,
            value: value,
            permissions: permissions,
            description: description,
            format: format,
            unit: unit,
            maxLength: maxLength,
            maxValue: maxValue,
            minValue: minValue,
            minStep: minStep,
            validValues: validValues,
            validValuesRange: validValuesRange)
    }

    static func supportedCharacteristicValueTransitionConfiguration(
        _ value: Data = Data(),
        permissions: [CharacteristicPermission] = [.read],
        description: String? = "Supported Characteristic Value Transition Configuration",
        format: CharacteristicFormat? = .tlv8,
        unit: CharacteristicUnit? = nil,
        maxLength: Int? = nil,
        maxValue: Double? = nil,
        minValue: Double? = nil,
        minStep: Double? = nil,
        validValues: [Double] = [],
        validValuesRange: Range<Double>? = nil
    ) -> GenericCharacteristic<Data> {
        return GenericCharacteristic<Data>(
            type: .supportedCharacteristicValueTransitionConfiguration,
            value: value,
            permissions: permissions,
            description: description,
            format: format,
            unit: unit,
            maxLength: maxLength,
            maxValue: maxValue,
            minValue: minValue,
            minStep: minStep,
            validValues: validValues,
            validValuesRange: validValuesRange)
    }

    static func supportedDiagnosticsSnapshot(
        _ value: Data = Data(),
        permissions: [CharacteristicPermission] = [.read],
        description: String? = "Supported Diagnostics Snapshot",
        format: CharacteristicFormat? = .tlv8,
        unit: CharacteristicUnit? = nil,
        maxLength: Int? = nil,
        maxValue: Double? = nil,
        minValue: Double? = nil,
        minStep: Double? = nil,
        validValues: [Double] = [],
        validValuesRange: Range<Double>? = nil
    ) -> GenericCharacteristic<Data> {
        return GenericCharacteristic<Data>(
            type: .supportedDiagnosticsSnapshot,
            value: value,
            permissions: permissions,
            description: description,
            format: format,
            unit: unit,
            maxLength: maxLength,
            maxValue: maxValue,
            minValue: minValue,
            minStep: minStep,
            validValues: validValues,
            validValuesRange: validValuesRange)
    }

    static func supportedTransferTransportConfiguration(
        _ value: Data = Data(),
        permissions: [CharacteristicPermission] = [.read],
        description: String? = "Supported Transfer Transport Configuration",
        format: CharacteristicFormat? = .tlv8,
        unit: CharacteristicUnit? = nil,
        maxLength: Int? = nil,
        maxValue: Double? = nil,
        minValue: Double? = nil,
        minStep: Double? = nil,
        validValues: [Double] = [],
        validValuesRange: Range<Double>? = nil
    ) -> GenericCharacteristic<Data> {
        return GenericCharacteristic<Data>(
            type: .supportedTransferTransportConfiguration,
            value: value,
            permissions: permissions,
            description: description,
            format: format,
            unit: unit,
            maxLength: maxLength,
            maxValue: maxValue,
            minValue: minValue,
            minStep: minStep,
            validValues: validValues,
            validValuesRange: validValuesRange)
    }

    static func swingMode(
        _ value: UInt8 = 0,
        permissions: [CharacteristicPermission] = [.read, .write, .events],
        description: String? = "Swing Mode",
        format: CharacteristicFormat? = .uint8,
        unit: CharacteristicUnit? = nil,
        maxLength: Int? = nil,
        maxValue: Double? = 1,
        minValue: Double? = 0,
        minStep: Double? = 1,
        validValues: [Double] = [],
        validValuesRange: Range<Double>? = nil
    ) -> GenericCharacteristic<UInt8> {
        return GenericCharacteristic<UInt8>(
            type: .swingMode,
            value: value,
            permissions: permissions,
            description: description,
            format: format,
            unit: unit,
            maxLength: maxLength,
            maxValue: maxValue,
            minValue: minValue,
            minStep: minStep,
            validValues: validValues,
            validValuesRange: validValuesRange)
    }

    static func targetAirPurifierState(
        _ value: Enums.TargetAirPurifierState = .auto,
        permissions: [CharacteristicPermission] = [.read, .write, .events],
        description: String? = "Target Air Purifier State",
        format: CharacteristicFormat? = .uint8,
        unit: CharacteristicUnit? = nil,
        maxLength: Int? = nil,
        maxValue: Double? = 1,
        minValue: Double? = 0,
        minStep: Double? = 1,
        validValues: [Double] = [],
        validValuesRange: Range<Double>? = nil
    ) -> GenericCharacteristic<Enums.TargetAirPurifierState> {
        return GenericCharacteristic<Enums.TargetAirPurifierState>(
            type: .targetAirPurifierState,
            value: value,
            permissions: permissions,
            description: description,
            format: format,
            unit: unit,
            maxLength: maxLength,
            maxValue: maxValue,
            minValue: minValue,
            minStep: minStep,
            validValues: validValues,
            validValuesRange: validValuesRange)
    }

    static func targetDoorState(
        _ value: Enums.TargetDoorState = .open,
        permissions: [CharacteristicPermission] = [.read, .write, .events],
        description: String? = "Target Door State",
        format: CharacteristicFormat? = .uint8,
        unit: CharacteristicUnit? = nil,
        maxLength: Int? = nil,
        maxValue: Double? = 1,
        minValue: Double? = 0,
        minStep: Double? = 1,
        validValues: [Double] = [],
        validValuesRange: Range<Double>? = nil
    ) -> GenericCharacteristic<Enums.TargetDoorState> {
        return GenericCharacteristic<Enums.TargetDoorState>(
            type: .targetDoorState,
            value: value,
            permissions: permissions,
            description: description,
            format: format,
            unit: unit,
            maxLength: maxLength,
            maxValue: maxValue,
            minValue: minValue,
            minStep: minStep,
            validValues: validValues,
            validValuesRange: validValuesRange)
    }

    static func targetFanState(
        _ value: Enums.TargetFanState = .auto,
        permissions: [CharacteristicPermission] = [.read, .write, .events],
        description: String? = "Target Fan State",
        format: CharacteristicFormat? = .uint8,
        unit: CharacteristicUnit? = nil,
        maxLength: Int? = nil,
        maxValue: Double? = 1,
        minValue: Double? = 0,
        minStep: Double? = 1,
        validValues: [Double] = [],
        validValuesRange: Range<Double>? = nil
    ) -> GenericCharacteristic<Enums.TargetFanState> {
        return GenericCharacteristic<Enums.TargetFanState>(
            type: .targetFanState,
            value: value,
            permissions: permissions,
            description: description,
            format: format,
            unit: unit,
            maxLength: maxLength,
            maxValue: maxValue,
            minValue: minValue,
            minStep: minStep,
            validValues: validValues,
            validValuesRange: validValuesRange)
    }

    static func targetHeaterCoolerState(
        _ value: Enums.TargetHeaterCoolerState = .auto,
        permissions: [CharacteristicPermission] = [.read, .write, .events],
        description: String? = "Target Heater-Cooler State",
        format: CharacteristicFormat? = .uint8,
        unit: CharacteristicUnit? = nil,
        maxLength: Int? = nil,
        maxValue: Double? = 2,
        minValue: Double? = 0,
        minStep: Double? = 1,
        validValues: [Double] = [],
        validValuesRange: Range<Double>? = nil
    ) -> GenericCharacteristic<Enums.TargetHeaterCoolerState> {
        return GenericCharacteristic<Enums.TargetHeaterCoolerState>(
            type: .targetHeaterCoolerState,
            value: value,
            permissions: permissions,
            description: description,
            format: format,
            unit: unit,
            maxLength: maxLength,
            maxValue: maxValue,
            minValue: minValue,
            minStep: minStep,
            validValues: validValues,
            validValuesRange: validValuesRange)
    }

    static func targetHeatingCoolingState(
        _ value: Enums.TargetHeatingCoolingState = .cool,
        permissions: [CharacteristicPermission] = [.read, .write, .events],
        description: String? = "Target Heating Cooling State",
        format: CharacteristicFormat? = .uint8,
        unit: CharacteristicUnit? = nil,
        maxLength: Int? = nil,
        maxValue: Double? = 3,
        minValue: Double? = 0,
        minStep: Double? = 1,
        validValues: [Double] = [],
        validValuesRange: Range<Double>? = nil
    ) -> GenericCharacteristic<Enums.TargetHeatingCoolingState> {
        return GenericCharacteristic<Enums.TargetHeatingCoolingState>(
            type: .targetHeatingCoolingState,
            value: value,
            permissions: permissions,
            description: description,
            format: format,
            unit: unit,
            maxLength: maxLength,
            maxValue: maxValue,
            minValue: minValue,
            minStep: minStep,
            validValues: validValues,
            validValuesRange: validValuesRange)
    }

    static func targetHorizontalTiltAngle(
        _ value: Int = -90,
        permissions: [CharacteristicPermission] = [.read, .write, .events],
        description: String? = "Target Horizontal Tilt Angle",
        format: CharacteristicFormat? = .int,
        unit: CharacteristicUnit? = .arcdegrees,
        maxLength: Int? = nil,
        maxValue: Double? = 90,
        minValue: Double? = -90,
        minStep: Double? = 1,
        validValues: [Double] = [],
        validValuesRange: Range<Double>? = nil
    ) -> GenericCharacteristic<Int> {
        return GenericCharacteristic<Int>(
            type: .targetHorizontalTiltAngle,
            value: value,
            permissions: permissions,
            description: description,
            format: format,
            unit: unit,
            maxLength: maxLength,
            maxValue: maxValue,
            minValue: minValue,
            minStep: minStep,
            validValues: validValues,
            validValuesRange: validValuesRange)
    }

    static func targetHumidifierDehumidifierState(
        _ value: Enums.TargetHumidifierDehumidifierState = .auto,
        permissions: [CharacteristicPermission] = [.read, .write, .events],
        description: String? = "Target Humidifier-Dehumidifier State",
        format: CharacteristicFormat? = .uint8,
        unit: CharacteristicUnit? = nil,
        maxLength: Int? = nil,
        maxValue: Double? = 2,
        minValue: Double? = 0,
        minStep: Double? = 1,
        validValues: [Double] = [],
        validValuesRange: Range<Double>? = nil
    ) -> GenericCharacteristic<Enums.TargetHumidifierDehumidifierState> {
        return GenericCharacteristic<Enums.TargetHumidifierDehumidifierState>(
            type: .targetHumidifierDehumidifierState,
            value: value,
            permissions: permissions,
            description: description,
            format: format,
            unit: unit,
            maxLength: maxLength,
            maxValue: maxValue,
            minValue: minValue,
            minStep: minStep,
            validValues: validValues,
            validValuesRange: validValuesRange)
    }

    static func targetMediaState(
        _ value: Enums.TargetMediaState = .pause,
        permissions: [CharacteristicPermission] = [.read, .write, .events],
        description: String? = "Target Media State",
        format: CharacteristicFormat? = .uint8,
        unit: CharacteristicUnit? = nil,
        maxLength: Int? = nil,
        maxValue: Double? = 2,
        minValue: Double? = 0,
        minStep: Double? = 1,
        validValues: [Double] = [],
        validValuesRange: Range<Double>? = nil
    ) -> GenericCharacteristic<Enums.TargetMediaState> {
        return GenericCharacteristic<Enums.TargetMediaState>(
            type: .targetMediaState,
            value: value,
            permissions: permissions,
            description: description,
            format: format,
            unit: unit,
            maxLength: maxLength,
            maxValue: maxValue,
            minValue: minValue,
            minStep: minStep,
            validValues: validValues,
            validValuesRange: validValuesRange)
    }

    static func targetPosition(
        _ value: UInt8 = 0,
        permissions: [CharacteristicPermission] = [.read, .write, .events],
        description: String? = "Target Position",
        format: CharacteristicFormat? = .uint8,
        unit: CharacteristicUnit? = .percentage,
        maxLength: Int? = nil,
        maxValue: Double? = 100,
        minValue: Double? = 0,
        minStep: Double? = 1,
        validValues: [Double] = [],
        validValuesRange: Range<Double>? = nil
    ) -> GenericCharacteristic<UInt8> {
        return GenericCharacteristic<UInt8>(
            type: .targetPosition,
            value: value,
            permissions: permissions,
            description: description,
            format: format,
            unit: unit,
            maxLength: maxLength,
            maxValue: maxValue,
            minValue: minValue,
            minStep: minStep,
            validValues: validValues,
            validValuesRange: validValuesRange)
    }

    static func targetRelativeHumidity(
        _ value: Float = 0,
        permissions: [CharacteristicPermission] = [.read, .write, .events],
        description: String? = "Target Relative Humidity",
        format: CharacteristicFormat? = .float,
        unit: CharacteristicUnit? = .percentage,
        maxLength: Int? = nil,
        maxValue: Double? = 100,
        minValue: Double? = 0,
        minStep: Double? = 1,
        validValues: [Double] = [],
        validValuesRange: Range<Double>? = nil
    ) -> GenericCharacteristic<Float> {
        return GenericCharacteristic<Float>(
            type: .targetRelativeHumidity,
            value: value,
            permissions: permissions,
            description: description,
            format: format,
            unit: unit,
            maxLength: maxLength,
            maxValue: maxValue,
            minValue: minValue,
            minStep: minStep,
            validValues: validValues,
            validValuesRange: validValuesRange)
    }

    static func targetTemperature(
        _ value: Float = 10,
        permissions: [CharacteristicPermission] = [.read, .write, .events],
        description: String? = "Target Temperature",
        format: CharacteristicFormat? = .float,
        unit: CharacteristicUnit? = .celsius,
        maxLength: Int? = nil,
        maxValue: Double? = 38,
        minValue: Double? = 10,
        minStep: Double? = 0.1,
        validValues: [Double] = [],
        validValuesRange: Range<Double>? = nil
    ) -> GenericCharacteristic<Float> {
        return GenericCharacteristic<Float>(
            type: .targetTemperature,
            value: value,
            permissions: permissions,
            description: description,
            format: format,
            unit: unit,
            maxLength: maxLength,
            maxValue: maxValue,
            minValue: minValue,
            minStep: minStep,
            validValues: validValues,
            validValuesRange: validValuesRange)
    }

    static func targetTiltAngle(
        _ value: Int = -90,
        permissions: [CharacteristicPermission] = [.read, .write, .events],
        description: String? = "Target Tilt Angle",
        format: CharacteristicFormat? = .int,
        unit: CharacteristicUnit? = .arcdegrees,
        maxLength: Int? = nil,
        maxValue: Double? = 90,
        minValue: Double? = -90,
        minStep: Double? = 1,
        validValues: [Double] = [],
        validValuesRange: Range<Double>? = nil
    ) -> GenericCharacteristic<Int> {
        return GenericCharacteristic<Int>(
            type: .targetTiltAngle,
            value: value,
            permissions: permissions,
            description: description,
            format: format,
            unit: unit,
            maxLength: maxLength,
            maxValue: maxValue,
            minValue: minValue,
            minStep: minStep,
            validValues: validValues,
            validValuesRange: validValuesRange)
    }

    static func targetVerticalTiltAngle(
        _ value: Int = -90,
        permissions: [CharacteristicPermission] = [.read, .write, .events],
        description: String? = "Target Vertical Tilt Angle",
        format: CharacteristicFormat? = .int,
        unit: CharacteristicUnit? = .arcdegrees,
        maxLength: Int? = nil,
        maxValue: Double? = 90,
        minValue: Double? = -90,
        minStep: Double? = 1,
        validValues: [Double] = [],
        validValuesRange: Range<Double>? = nil
    ) -> GenericCharacteristic<Int> {
        return GenericCharacteristic<Int>(
            type: .targetVerticalTiltAngle,
            value: value,
            permissions: permissions,
            description: description,
            format: format,
            unit: unit,
            maxLength: maxLength,
            maxValue: maxValue,
            minValue: minValue,
            minStep: minStep,
            validValues: validValues,
            validValuesRange: validValuesRange)
    }

    static func targetVisibilityState(
        _ value: Enums.TargetVisibilityState = .shown,
        permissions: [CharacteristicPermission] = [.read, .write, .events],
        description: String? = "Target Visibility State",
        format: CharacteristicFormat? = .uint8,
        unit: CharacteristicUnit? = nil,
        maxLength: Int? = nil,
        maxValue: Double? = 1,
        minValue: Double? = 0,
        minStep: Double? = 1,
        validValues: [Double] = [],
        validValuesRange: Range<Double>? = nil
    ) -> GenericCharacteristic<Enums.TargetVisibilityState> {
        return GenericCharacteristic<Enums.TargetVisibilityState>(
            type: .targetVisibilityState,
            value: value,
            permissions: permissions,
            description: description,
            format: format,
            unit: unit,
            maxLength: maxLength,
            maxValue: maxValue,
            minValue: minValue,
            minStep: minStep,
            validValues: validValues,
            validValuesRange: validValuesRange)
    }

    static func temperatureDisplayUnits(
        _ value: Enums.TemperatureDisplayUnits = .celcius,
        permissions: [CharacteristicPermission] = [.read, .write, .events],
        description: String? = "Temperature Display Units",
        format: CharacteristicFormat? = .uint8,
        unit: CharacteristicUnit? = nil,
        maxLength: Int? = nil,
        maxValue: Double? = 1,
        minValue: Double? = 0,
        minStep: Double? = 1,
        validValues: [Double] = [],
        validValuesRange: Range<Double>? = nil
    ) -> GenericCharacteristic<Enums.TemperatureDisplayUnits> {
        return GenericCharacteristic<Enums.TemperatureDisplayUnits>(
            type: .temperatureDisplayUnits,
            value: value,
            permissions: permissions,
            description: description,
            format: format,
            unit: unit,
            maxLength: maxLength,
            maxValue: maxValue,
            minValue: minValue,
            minStep: minStep,
            validValues: validValues,
            validValuesRange: validValuesRange)
    }

    static func threadControlPoint(
        _ value: Data? = nil,
        permissions: [CharacteristicPermission] = [.write],
        description: String? = "Thread Control Point",
        format: CharacteristicFormat? = .tlv8,
        unit: CharacteristicUnit? = nil,
        maxLength: Int? = nil,
        maxValue: Double? = nil,
        minValue: Double? = nil,
        minStep: Double? = nil,
        validValues: [Double] = [],
        validValuesRange: Range<Double>? = nil
    ) -> GenericCharacteristic<Data?> {
        return GenericCharacteristic<Data?>(
            type: .threadControlPoint,
            value: value,
            permissions: permissions,
            description: description,
            format: format,
            unit: unit,
            maxLength: maxLength,
            maxValue: maxValue,
            minValue: minValue,
            minStep: minStep,
            validValues: validValues,
            validValuesRange: validValuesRange)
    }

    static func threadNodeCapabilities(
        _ value: UInt16 = 0,
        permissions: [CharacteristicPermission] = [.read],
        description: String? = "Thread Node Capabilities",
        format: CharacteristicFormat? = .uint16,
        unit: CharacteristicUnit? = nil,
        maxLength: Int? = nil,
        maxValue: Double? = 31,
        minValue: Double? = 0,
        minStep: Double? = 1,
        validValues: [Double] = [],
        validValuesRange: Range<Double>? = nil
    ) -> GenericCharacteristic<UInt16> {
        return GenericCharacteristic<UInt16>(
            type: .threadNodeCapabilities,
            value: value,
            permissions: permissions,
            description: description,
            format: format,
            unit: unit,
            maxLength: maxLength,
            maxValue: maxValue,
            minValue: minValue,
            minStep: minStep,
            validValues: validValues,
            validValuesRange: validValuesRange)
    }

    static func threadOpenthreadVersion(
        _ value: String = "",
        permissions: [CharacteristicPermission] = [.read],
        description: String? = "Thread OpenThread Version",
        format: CharacteristicFormat? = .string,
        unit: CharacteristicUnit? = nil,
        maxLength: Int? = nil,
        maxValue: Double? = nil,
        minValue: Double? = nil,
        minStep: Double? = nil,
        validValues: [Double] = [],
        validValuesRange: Range<Double>? = nil
    ) -> GenericCharacteristic<String> {
        return GenericCharacteristic<String>(
            type: .threadOpenthreadVersion,
            value: value,
            permissions: permissions,
            description: description,
            format: format,
            unit: unit,
            maxLength: maxLength,
            maxValue: maxValue,
            minValue: minValue,
            minStep: minStep,
            validValues: validValues,
            validValuesRange: validValuesRange)
    }

    static func threadStatus(
        _ value: UInt16 = 0,
        permissions: [CharacteristicPermission] = [.read, .events],
        description: String? = "Thread Status",
        format: CharacteristicFormat? = .uint16,
        unit: CharacteristicUnit? = nil,
        maxLength: Int? = nil,
        maxValue: Double? = 6,
        minValue: Double? = 0,
        minStep: Double? = 1,
        validValues: [Double] = [],
        validValuesRange: Range<Double>? = nil
    ) -> GenericCharacteristic<UInt16> {
        return GenericCharacteristic<UInt16>(
            type: .threadStatus,
            value: value,
            permissions: permissions,
            description: description,
            format: format,
            unit: unit,
            maxLength: maxLength,
            maxValue: maxValue,
            minValue: minValue,
            minStep: minStep,
            validValues: validValues,
            validValuesRange: validValuesRange)
    }

    static func transmitPower(
        _ value: Int = 0,
        permissions: [CharacteristicPermission] = [.read],
        description: String? = "Transmit Power",
        format: CharacteristicFormat? = .int,
        unit: CharacteristicUnit? = nil,
        maxLength: Int? = nil,
        maxValue: Double? = nil,
        minValue: Double? = nil,
        minStep: Double? = nil,
        validValues: [Double] = [],
        validValuesRange: Range<Double>? = nil
    ) -> GenericCharacteristic<Int> {
        return GenericCharacteristic<Int>(
            type: .transmitPower,
            value: value,
            permissions: permissions,
            description: description,
            format: format,
            unit: unit,
            maxLength: maxLength,
            maxValue: maxValue,
            minValue: minValue,
            minStep: minStep,
            validValues: validValues,
            validValuesRange: validValuesRange)
    }

    static func valveType(
        _ value: UInt8 = 0,
        permissions: [CharacteristicPermission] = [.read, .events],
        description: String? = "Valve Type",
        format: CharacteristicFormat? = .uint8,
        unit: CharacteristicUnit? = nil,
        maxLength: Int? = nil,
        maxValue: Double? = 3,
        minValue: Double? = 0,
        minStep: Double? = 1,
        validValues: [Double] = [],
        validValuesRange: Range<Double>? = nil
    ) -> GenericCharacteristic<UInt8> {
        return GenericCharacteristic<UInt8>(
            type: .valveType,
            value: value,
            permissions: permissions,
            description: description,
            format: format,
            unit: unit,
            maxLength: maxLength,
            maxValue: maxValue,
            minValue: minValue,
            minStep: minStep,
            validValues: validValues,
            validValuesRange: validValuesRange)
    }

    static func version(
        _ value: String = "",
        permissions: [CharacteristicPermission] = [.read, .events],
        description: String? = "Version",
        format: CharacteristicFormat? = .string,
        unit: CharacteristicUnit? = nil,
        maxLength: Int? = nil,
        maxValue: Double? = nil,
        minValue: Double? = nil,
        minStep: Double? = nil,
        validValues: [Double] = [],
        validValuesRange: Range<Double>? = nil
    ) -> GenericCharacteristic<String> {
        return GenericCharacteristic<String>(
            type: .version,
            value: value,
            permissions: permissions,
            description: description,
            format: format,
            unit: unit,
            maxLength: maxLength,
            maxValue: maxValue,
            minValue: minValue,
            minStep: minStep,
            validValues: validValues,
            validValuesRange: validValuesRange)
    }

    static func volatileOrganicCompoundDensity(
        _ value: Float = 0,
        permissions: [CharacteristicPermission] = [.read, .events],
        description: String? = "Volatile Organic Compound Density",
        format: CharacteristicFormat? = .float,
        unit: CharacteristicUnit? = .microgramsPerMCubed,
        maxLength: Int? = nil,
        maxValue: Double? = 1000,
        minValue: Double? = 0,
        minStep: Double? = 1,
        validValues: [Double] = [],
        validValuesRange: Range<Double>? = nil
    ) -> GenericCharacteristic<Float> {
        return GenericCharacteristic<Float>(
            type: .volatileOrganicCompoundDensity,
            value: value,
            permissions: permissions,
            description: description,
            format: format,
            unit: unit,
            maxLength: maxLength,
            maxValue: maxValue,
            minValue: minValue,
            minStep: minStep,
            validValues: validValues,
            validValuesRange: validValuesRange)
    }

    static func volume(
        _ value: UInt8 = 0,
        permissions: [CharacteristicPermission] = [.read, .write, .events],
        description: String? = "Volume",
        format: CharacteristicFormat? = .uint8,
        unit: CharacteristicUnit? = .percentage,
        maxLength: Int? = nil,
        maxValue: Double? = 100,
        minValue: Double? = 0,
        minStep: Double? = 1,
        validValues: [Double] = [],
        validValuesRange: Range<Double>? = nil
    ) -> GenericCharacteristic<UInt8> {
        return GenericCharacteristic<UInt8>(
            type: .volume,
            value: value,
            permissions: permissions,
            description: description,
            format: format,
            unit: unit,
            maxLength: maxLength,
            maxValue: maxValue,
            minValue: minValue,
            minStep: minStep,
            validValues: validValues,
            validValuesRange: validValuesRange)
    }

    static func volumeControlType(
        _ value: Enums.VolumeControlType = .relativewithcurrent,
        permissions: [CharacteristicPermission] = [.read, .events],
        description: String? = "Volume Control Type",
        format: CharacteristicFormat? = .uint8,
        unit: CharacteristicUnit? = nil,
        maxLength: Int? = nil,
        maxValue: Double? = 3,
        minValue: Double? = 0,
        minStep: Double? = 1,
        validValues: [Double] = [],
        validValuesRange: Range<Double>? = nil
    ) -> GenericCharacteristic<Enums.VolumeControlType> {
        return GenericCharacteristic<Enums.VolumeControlType>(
            type: .volumeControlType,
            value: value,
            permissions: permissions,
            description: description,
            format: format,
            unit: unit,
            maxLength: maxLength,
            maxValue: maxValue,
            minValue: minValue,
            minStep: minStep,
            validValues: validValues,
            validValuesRange: validValuesRange)
    }

    static func volumeSelector(
        _ value: Enums.VolumeSelector? = nil,
        permissions: [CharacteristicPermission] = [.write],
        description: String? = "Volume Selector",
        format: CharacteristicFormat? = .uint8,
        unit: CharacteristicUnit? = nil,
        maxLength: Int? = nil,
        maxValue: Double? = 1,
        minValue: Double? = 0,
        minStep: Double? = 1,
        validValues: [Double] = [],
        validValuesRange: Range<Double>? = nil
    ) -> GenericCharacteristic<Enums.VolumeSelector?> {
        return GenericCharacteristic<Enums.VolumeSelector?>(
            type: .volumeSelector,
            value: value,
            permissions: permissions,
            description: description,
            format: format,
            unit: unit,
            maxLength: maxLength,
            maxValue: maxValue,
            minValue: minValue,
            minStep: minStep,
            validValues: validValues,
            validValuesRange: validValuesRange)
    }

    static func wiFiCapabilities(
        _ value: UInt32 = 0,
        permissions: [CharacteristicPermission] = [.read],
        description: String? = "Wi-Fi Capabilities",
        format: CharacteristicFormat? = .uint32,
        unit: CharacteristicUnit? = nil,
        maxLength: Int? = nil,
        maxValue: Double? = nil,
        minValue: Double? = nil,
        minStep: Double? = nil,
        validValues: [Double] = [],
        validValuesRange: Range<Double>? = nil
    ) -> GenericCharacteristic<UInt32> {
        return GenericCharacteristic<UInt32>(
            type: .wiFiCapabilities,
            value: value,
            permissions: permissions,
            description: description,
            format: format,
            unit: unit,
            maxLength: maxLength,
            maxValue: maxValue,
            minValue: minValue,
            minStep: minStep,
            validValues: validValues,
            validValuesRange: validValuesRange)
    }

    static func wiFiConfigurationControl(
        _ value: Data = Data(),
        permissions: [CharacteristicPermission] = [.read, .write, .events],
        description: String? = "Wi-Fi Configuration Control",
        format: CharacteristicFormat? = .tlv8,
        unit: CharacteristicUnit? = nil,
        maxLength: Int? = nil,
        maxValue: Double? = nil,
        minValue: Double? = nil,
        minStep: Double? = nil,
        validValues: [Double] = [],
        validValuesRange: Range<Double>? = nil
    ) -> GenericCharacteristic<Data> {
        return GenericCharacteristic<Data>(
            type: .wiFiConfigurationControl,
            value: value,
            permissions: permissions,
            description: description,
            format: format,
            unit: unit,
            maxLength: maxLength,
            maxValue: maxValue,
            minValue: minValue,
            minStep: minStep,
            validValues: validValues,
            validValuesRange: validValuesRange)
    }

}
