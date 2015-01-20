//*****************************************************************************
//
// Application Name     -   washerAlert
// Application Overview -   washerAlert monitors a washer or dryer, via a
//                            microphone. When the washer or dryer stops, the
//                            application publishes an alert to Amazon SNS.
//
//*****************************************************************************


//****************************************************************************
//
//! \addtogroup washerAlert
//! @{
//
//****************************************************************************

//TODO: cleanup unused includes

// Standard includes
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <stdbool.h>

// simplelink includes
#include "simplelink.h"

// driverlib includes
#include "hw_types.h"
#include "hw_ints.h"
#include "hw_memmap.h"
#include "interrupt.h"
#include "prcm.h"
#include "pin.h"
#include "rom.h"
#include "rom_map.h"
#include "timer.h"
#include "utils.h"
#include "hw_shamd5.h"
#include "hw_common_reg.h"
#include "shamd5.h"
#include "uart.h"
#include "adc.h"
#include "gpio.h"

//Free_rtos/ti-rtos includes
#include "osi.h"

// common interface includes
#include "network_if.h"
#ifndef NOTERM
#include "uart_if.h"
#endif
#include "gpio_if.h"
#include "timer_if.h"
#include "udma_if.h"
#include "pinmux.h"
#include "common.h"

#include "auth.h"

#define APP_NAME                "washerAlert"
#define APPLICATION_VERSION     "0.1.0"

#define TIME2013                3565987200u      /* 113 years + 28 days(leap) */
#define YEAR2013                2013
#define SEC_IN_MIN              60
#define SEC_IN_HOUR             3600
#define SEC_IN_DAY              86400

#define SERVER_RESPONSE_TIMEOUT 10

#define REQUEST_PREFIX			"POST / HTTP/1.1\n\
Host: sns.us-east-1.amazonaws.com\n\
Content-Type: application/x-www-form-urlencoded; charset=UTF-8\n\
Content-Length: "
#define REQUEST_DATE_HEADER		"X-Amz-Date: "
#define	REQUEST_AUTH_HEADER		"Authorization: AWS4-HMAC-SHA256 Credential="
#define REQUEST_AUTH_SUFFIX		"/us-east-1/sns/aws4_request,SignedHeaders=host;x-amz-date,Signature="
#define REQUEST_PREPAYLOAD		"\n\n"
#define REQUEST_PAYLOAD_PREFIX	"Action=Publish\
&Message=The washer has stopped\
&TopicArn="
#define REQUEST_PAYLOAD_SUFFIX	"&Version=2010-03-31"

#define SECRET_KEY_PREFIX		"AWS4"
#define SNS_REGION			"us-east-1"
#define SNS_SERVICE			"sns"
#define SNS_REQUEST_KEY		"aws4_request"

#define CANONIC_REQUEST_PREFIX	"POST\n\
/\n\
\n\
host:sns.us-east-1.amazonaws.com\n\
x-amz-date:"
#define CANONIC_REQUEST_SUFFIX	"\n\nhost;x-amz-date\n"

#define STRING_TO_SIGN_ALGO		"AWS4-HMAC-SHA256\n"
#define STRING_TO_SIGN_SCOPE	"/us-east-1/sns/aws4_request\n"

#define MIC_INPUT_CHANNEL		ADC_CH_1 // ADC channel 1 is P58 on the CC3200 launchpad
#define MIC_NUMBER_OF_SAMPLES	50
#define MIC_SAMPLE_INTERVAL		1000  // Clock Cycles
#define AMPLITUDE_INTERVAL		1  // Seconds
#define MIC_THRESHOLD			25  // millivolts
#define START_THRESHHOLD_NUM	3
#define FINISH_THRESHHOLD_NUM	10

#define SLEEP_TIME              80000000
#define OSI_STACK_SIZE          4096

//*****************************************************************************
//                 GLOBAL VARIABLES -- Start
//*****************************************************************************
// Application specific status/error codes
typedef enum{
    // Choosing -0x7D0 to avoid overlap w/ host-driver's error codes
    SERVER_GET_TIME_FAILED = -0x7D0,
    DNS_LOOPUP_FAILED = SERVER_GET_TIME_FAILED  -1,

    STATUS_CODE_MAX = -0xBB8
}e_AppStatusCodes;

unsigned short g_usTimerInts;
SlSecParams_t SecurityParams = {0};

#if defined(ccs) || defined(gcc)
extern void (* const g_pfnVectors[])(void);
#endif
#if defined(ewarm)
extern uVectorEntry __vector_table;
#endif

//!    ######################### list of SNTP servers ##################################
//!    ##
//!    ##          hostname         |        IP       |       location
//!    ## -----------------------------------------------------------------------------
//!    ##   nist1-nj2.ustiming.org  | 165.193.126.229 |  Weehawken, NJ
//!    ##   nist1-pa.ustiming.org   | 206.246.122.250 |  Hatfield, PA
//!    ##   time-a.nist.gov         | 129.6.15.28     |  NIST, Gaithersburg, Maryland
//!    ##   time-b.nist.gov         | 129.6.15.29     |  NIST, Gaithersburg, Maryland
//!    ##   time-c.nist.gov         | 129.6.15.30     |  NIST, Gaithersburg, Maryland
//!    ##   ntp-nist.ldsbc.edu      | 198.60.73.8     |  LDSBC, Salt Lake City, Utah
//!    ##   nist1-macon.macon.ga.us | 98.175.203.200  |  Macon, Georgia
//!
//!    ##   For more SNTP server link visit 'http://tf.nist.gov/tf-cgi/servers.cgi'
//!    ###################################################################################
const char g_acSNTPserver[30] = "time-a.nist.gov"; //Add any one of the above servers

//// Tuesday is the 1st day in 2013 - the relative year
//const char g_acDaysOfWeek2013[7][3] = {{"Tue"},
//                                    {"Wed"},
//                                    {"Thu"},
//                                    {"Fri"},
//                                    {"Sat"},
//                                    {"Sun"},
//                                    {"Mon"}};
//
//const char g_acMonthOfYear[12][3] = {{"Jan"},
//                                  {"Feb"},
//                                  {"Mar"},
//                                  {"Apr"},
//                                  {"May"},
//                                  {"Jun"},
//                                  {"Jul"},
//                                  {"Aug"},
//                                  {"Sep"},
//                                  {"Oct"},
//                                  {"Nov"},
//                                  {"Dec"}};

const char g_acNumOfDaysPerMonth[12] = {31, 28, 31, 30, 31, 30,
                                        31, 31, 30, 31, 30, 31};

const char g_acDigits[] = "0123456789";

//struct
//{
//    unsigned long ulDestinationIP;
//    int iSockID;
//    unsigned long ulElapsedSec;
//    short isGeneralVar;
//    unsigned long ulGeneralVar;
//    unsigned long ulGeneralVar1;
//    char acTimeStore[30];
//    char *pcCCPtr;
//    unsigned short uisCCLen;
//}g_sAppData; // TODO: get rid of this global variable/struct nonsense

const char g_ServerAddress[30] = "sns.us-east-1.amazonaws.com";

// Flags to check that SHAMD5 interrupts were successfully generated.
volatile bool g_bContextReadyFlag;
volatile bool g_bParthashReadyFlag;
volatile bool g_bInputReadyFlag;
volatile bool g_bOutputReadyFlag;

SlSockAddr_t sAddr;
SlSockAddrIn_t sLocalAddr;
//*****************************************************************************
//                 GLOBAL VARIABLES -- End
//*****************************************************************************



//*****************************************************************************
//                      LOCAL FUNCTION PROTOTYPES
//*****************************************************************************
void MonitorWasherTask(void *pvParameters);
static void DisplayBanner(char * AppName);
int SampleADC(unsigned int uiNumSamples, unsigned int uiChannel);
int WaitForStart(void);
int WaitForFinish(void);
static int CreateConnection(unsigned long ulDestinationIP);
void PublishSNS(char *pcSNSTopic);  //TODO: return error codes?
void GetDatetime(char *pcDatetime);
static long GetSNTPTime(char * pcResult, unsigned long ulDestinationIP, int iSockID);
void SHAMD5IntHandler(void);
void GenerateSignature(char * pcHashResult, char *pcDatetime, char *pcDate);  //TODO: return error codes?
void HexToString(char * pcHex, unsigned int uiHexLength, char * pcConvertedString);
char HexNibbleToChar(unsigned int uiHexNibble);
long POSTToSNS(int iSockID, char *pcSNSTopic);  //TODO: return error codes?

void SetupButtonInterrupts();
void SW3InterruptHandler();
void SW2InterruptHandler();

//*****************************************************************************
//
//! Reads the specified number of samples from an external ADS7841 and returns
//!
//! \brief  This function reads the ADC
//!
//! \param uiNumSamples is the number of samples to collect
//! \param uiChannel indicates which ADC channel to read, as defined in driverlib/adc.h
//!
//! \return the difference between the highest and lowest sample readings in millivolts  //TODO: clarify this description
//!
//
//*****************************************************************************
int SampleADC(unsigned int uiNumSamples, unsigned int uiChannel)
{
	unsigned int uiMax = 0x000;
	unsigned int uiMin = 0x400;
	unsigned int uiSample, uiAmplitude;


	// Pinmux for the ADC input pin 58
	MAP_PinTypeADC(PIN_58, PIN_MODE_255);
	// Enable ADC channel
	MAP_ADCChannelEnable(ADC_BASE, uiChannel);
	// Configure ADC timer which is used to timestamp the ADC data samples
	MAP_ADCTimerConfig(ADC_BASE,2^17);
	// Enable ADC timer which is used to timestamp the ADC data samples
	MAP_ADCTimerEnable(ADC_BASE);
	// Enable ADC module
	MAP_ADCEnable(ADC_BASE);

	while(uiNumSamples)
	{
		// MAP_ADCFIFORead returns a value with:
		//    bits[13:2] : ADC sample
		//    bits[31:14]: Time stamp of ADC sample
		// We only want the ADC sample, not the timestamp.
		// Also, the ADC has an effective nominal accuracy of 10 bits, so we
		//    are only interested in bits[13:4] of the returned value
		uiSample = (MAP_ADCFIFORead(ADC_BASE, uiChannel)>>4) & 0x3FF;
		if(uiSample > uiMax)
		{
			uiMax = uiSample;
		}
		else if(uiSample < uiMin)
		{
			uiMin = uiSample;
		}

		MAP_UtilsDelay(MIC_SAMPLE_INTERVAL);

		uiNumSamples--;
	}

	// Find the amplitude
	uiAmplitude = uiMax - uiMin;

	// Convert the result into millivolts
	uiAmplitude = (1320 * uiAmplitude) / 1024;

	UART_PRINT("%i\r\n", uiAmplitude);

	return uiAmplitude;
}

//*****************************************************************************
//
//! Waits until the washer sounds are detected
//!
//! \brief  This function blocks the process until the washer starts
//!
//! \return 0 on success, < 0 on failure
//!
//
//*****************************************************************************
int WaitForStart(void)
{
	unsigned int uiAmplitude = 0;
	unsigned int uiCount = 0;

	UART_PRINT("Waiting for the washer to start.\r\n");
	while(uiCount<START_THRESHHOLD_NUM)
	{
		MAP_UtilsDelay(13333333 * AMPLITUDE_INTERVAL);  // TODO: use HW timers instead of a delay
		uiAmplitude = SampleADC(MIC_NUMBER_OF_SAMPLES , MIC_INPUT_CHANNEL);
		if(uiAmplitude>MIC_THRESHOLD)
		{
			uiCount++;
		}
		else
		{
			uiCount = 0;
		}
	}
	UART_PRINT("The washer has started.\r\n");

	// TODO: error codes
	return 0;
}

//*****************************************************************************
//
//! Waits until the washer sounds are detected
//!
//! \brief  This function blocks the process until the washer stops
//!
//! \return 0 on success, < 0 on failure
//!
//
//*****************************************************************************
int WaitForFinish(void)
{
	unsigned int uiAmplitude = 0;
	unsigned int uiCount = 0;

	UART_PRINT("Waiting for the washer to finish.\r\n");
	while(uiCount<FINISH_THRESHHOLD_NUM)
	{
		MAP_UtilsDelay(13333333 * AMPLITUDE_INTERVAL);  // TODO: use HW timers instead of a delay
		uiAmplitude = SampleADC(MIC_NUMBER_OF_SAMPLES , MIC_INPUT_CHANNEL);
		if(uiAmplitude<MIC_THRESHOLD)
		{
			uiCount++;
		}
		else
		{
			uiCount = 0;
		}
	}
	UART_PRINT("The washer has finished.\r\n");

	// TODO: error codes
	return 0;
}

//*****************************************************************************
//
//! CreateConnection
//!
//! \brief  Creating an endpoint for TCP communication and initiating
//!         connection on socket
//!
//! \param  The server hostname
//!
//! \return SocketID on Success or < 0 on Failure.
//!
//
//*****************************************************************************
static int CreateConnection(unsigned long ulDestinationIP)
{
    int iLenorError;
    SlSockAddrIn_t  sAddr;
    int iAddrSize;
    int iSockIDorError = 0;

    sAddr.sin_family = SL_AF_INET;
    sAddr.sin_port = sl_Htons(80);

    //Change the DestinationIP endianity , to big endian
    sAddr.sin_addr.s_addr = sl_Htonl(ulDestinationIP);

    iAddrSize = sizeof(SlSockAddrIn_t);

    iSockIDorError = sl_Socket(SL_AF_INET,SL_SOCK_STREAM, 0);
    ASSERT_ON_ERROR(iSockIDorError);

    iLenorError = sl_Connect(iSockIDorError, ( SlSockAddr_t *)&sAddr, iAddrSize);
    ASSERT_ON_ERROR(iLenorError);

    DBG_PRINT("Socket Id: %d was created.\n\r",iSockIDorError);

    return iSockIDorError;//success, connection created
}

//*****************************************************************************
//
//! Publishes to the specified SNS topic
//!
//! \brief  This function publishes a message to the specified SNS topic.
//!
//! \param  pcSNSTopic is a pointer to the topic ARN string.
//!
//! \return none
//!
//
//*****************************************************************************
void PublishSNS(char *pcSNSTopic)
{
	int iSocketDesc;
	long lRetVal = -1;
	unsigned long ulDestinationIP;

	//
	// Get the serverhost IP address using the DNS lookup
	//
	lRetVal = Network_IF_GetHostIP((char*)g_ServerAddress, &ulDestinationIP);
	if(lRetVal < 0)
	{
		UART_PRINT("DNS lookup failed. \n\r",lRetVal);
//		goto end;
	}

	//
	// Create a TCP connection to the SNS server
	//
	iSocketDesc = CreateConnection(ulDestinationIP);
	if(iSocketDesc < 0)
	{
		DBG_PRINT("Socket creation failed.\n\r");
//		goto end;
	}

	struct SlTimeval_t timeVal;
	timeVal.tv_sec =  SERVER_RESPONSE_TIMEOUT;    // Seconds
	timeVal.tv_usec = 0;     // Microseconds. 10000 microseconds resolution
	lRetVal = sl_SetSockOpt(iSocketDesc,SL_SOL_SOCKET,SL_SO_RCVTIMEO,\
					(char*)&timeVal, sizeof(timeVal));
	if(lRetVal < 0)
	{
	   ERR_PRINT(lRetVal);
	   LOOP_FOREVER();
	}

	lRetVal = POSTToSNS(iSocketDesc, pcSNSTopic);
}

//*****************************************************************************
//
//! Connects to the NTP server and retrieves the date and time.
//!
//! \brief  Connects to the NTP server and retrieves the date and time.
//!
//! \param  pcDatetime is a pointer to where we will store the datetime.
//!           The allocated memory must be at least 17 chars in length.
//!
//! \return none
//!
//
//*****************************************************************************
void GetDatetime(char *pcDatetime)
{
	long lRetVal = -1;
	unsigned long ulDestinationIP;
	int iSockID;

    //
    // Create UDP socket for NTP
    //
    int iSocketDesc;
    iSocketDesc = sl_Socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if(iSocketDesc < 0)
    {
        ERR_PRINT(iSocketDesc);
//        goto end; // TODO:
    }
    iSockID = iSocketDesc;

    UART_PRINT("NTP Socket created\n\r");

    //
    // Get the NTP server host IP address using the DNS lookup
    //
    lRetVal = Network_IF_GetHostIP((char*)g_acSNTPserver, \
                                    &ulDestinationIP);

    if( lRetVal >= 0)
    {

        struct SlTimeval_t timeVal;
        timeVal.tv_sec =  SERVER_RESPONSE_TIMEOUT;    // Seconds
        timeVal.tv_usec = 0;     // Microseconds. 10000 microseconds resolution
        lRetVal = sl_SetSockOpt(iSockID,SL_SOL_SOCKET,SL_SO_RCVTIMEO,\
                        (char*)&timeVal, sizeof(timeVal));
        if(lRetVal < 0)
        {
           ERR_PRINT(lRetVal);
           LOOP_FOREVER();
        }

		//
		// Get the NTP time and display the time
		//
		lRetVal = GetSNTPTime(pcDatetime, ulDestinationIP, iSockID);
		if(lRetVal < 0)
		{
			UART_PRINT("Server Get Time failed\n\r");
		}

		//
		// Wait a while before resuming
		//
		MAP_UtilsDelay(SLEEP_TIME);
    }
    else
    {
        UART_PRINT("DNS lookup of NTP server failed. \n\r");
    }

    //
    // Close the NTP socket
    //
    close(iSocketDesc);
    UART_PRINT("NTP Socket closed\n\r");
}

//*****************************************************************************
//
//! Gets the current time from the selected SNTP server
//!
//! \brief  This function obtains the NTP time from the server.
//!
//! \param  pcResult is where we will store the result. Must be at least 17 chars long.
//! \param  ulDestinationIP is 4 bytes representing th IP of the NTP server
//! \param  iSockID is the socket ID of the NTP connection
//!
//! \return 0 : success, -ve : failure
//!
//
//*****************************************************************************
long GetSNTPTime(char * pcResult, unsigned long ulDestinationIP, int iSockID)
{
  
/*
                            NTP Packet Header:


       0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9  0  1
      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
      |LI | VN  |Mode |    Stratum    |     Poll      |   Precision    |
      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
      |                          Root  Delay                           |
      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
      |                       Root  Dispersion                         |
      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
      |                     Reference Identifier                       |
      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
      |                                                                |
      |                    Reference Timestamp (64)                    |
      |                                                                |
      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
      |                                                                |
      |                    Originate Timestamp (64)                    |
      |                                                                |
      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
      |                                                                |
      |                     Receive Timestamp (64)                     |
      |                                                                |
      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
      |                                                                |
      |                     Transmit Timestamp (64)                    |
      |                                                                |
      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
      |                 Key Identifier (optional) (32)                 |
      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
      |                                                                |
      |                                                                |
      |                 Message Digest (optional) (128)                |
      |                                                                |
      |                                                                |
      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

*/
    char cDataBuf[48];
    long lRetVal = 0;
    int iAddrSize;
    unsigned long ulElapsedSec;
	short isGeneralVar;
	unsigned long ulGeneralVar;
	unsigned long ulGeneralVar1;
	char acTimeStore[17];
	char *pcCCPtr;
	unsigned short uisCCLen;
    //
    // Send a query ? to the NTP server to get the NTP time
    //
    memset(cDataBuf, 0, sizeof(cDataBuf));
    cDataBuf[0] = '\x1b';

    sAddr.sa_family = AF_INET;
    // the source port
    sAddr.sa_data[0] = 0x00;
    sAddr.sa_data[1] = 0x7B;    // UDP port number for NTP is 123
    sAddr.sa_data[2] = (char)((ulDestinationIP>>24)&0xff);
    sAddr.sa_data[3] = (char)((ulDestinationIP>>16)&0xff);
    sAddr.sa_data[4] = (char)((ulDestinationIP>>8)&0xff);
    sAddr.sa_data[5] = (char)(ulDestinationIP&0xff);

    lRetVal = sl_SendTo(iSockID,
                     cDataBuf,
                     sizeof(cDataBuf), 0,
                     &sAddr, sizeof(sAddr));
    if (lRetVal != sizeof(cDataBuf))
    {
        // could not send SNTP request
        ASSERT_ON_ERROR(SERVER_GET_TIME_FAILED);
    }

    //
    // Wait to receive the NTP time from the server
    //
    sLocalAddr.sin_family = SL_AF_INET;
    sLocalAddr.sin_port = 0;
    sLocalAddr.sin_addr.s_addr = 0;
    if(ulElapsedSec == 0)
    {
        lRetVal = sl_Bind(iSockID,
                (SlSockAddr_t *)&sLocalAddr,
                sizeof(SlSockAddrIn_t));
    }

    iAddrSize = sizeof(SlSockAddrIn_t);

    lRetVal = sl_RecvFrom(iSockID,
                       cDataBuf, sizeof(cDataBuf), 0,
                       (SlSockAddr_t *)&sLocalAddr,
                       (SlSocklen_t*)&iAddrSize);
    ASSERT_ON_ERROR(lRetVal);

    //
    // Confirm that the MODE is 4 --> server
    //
    if ((cDataBuf[0] & 0x7) != 4)    // expect only server response
    {
         ASSERT_ON_ERROR(SERVER_GET_TIME_FAILED);  // MODE is not server, abort
    }
    else
    {
        unsigned int iIndex;

        //
        // Getting the data from the Transmit Timestamp (seconds) field
        // This is the time at which the reply departed the
        // server for the client
        //
        ulElapsedSec = cDataBuf[40];
        ulElapsedSec <<= 8;
        ulElapsedSec += cDataBuf[41];
        ulElapsedSec <<= 8;
        ulElapsedSec += cDataBuf[42];
        ulElapsedSec <<= 8;
        ulElapsedSec += cDataBuf[43];

        //
        // Received seconds are relative to 0h on 1 January 1900.
        // Convert them to be relative to 2013, so that the are easier to work with
        //
        ulElapsedSec -= TIME2013;

        pcCCPtr = &acTimeStore[0];

		// year
		// number of days since beginning of 2013
		ulGeneralVar = ulElapsedSec/SEC_IN_DAY;
		ulGeneralVar /= 365;
		uisCCLen = itoa(YEAR2013 + ulGeneralVar,
								   pcCCPtr);
		pcCCPtr += uisCCLen;

		// month
		isGeneralVar = (ulElapsedSec/SEC_IN_DAY) % 365;
		for (iIndex = 0; iIndex < 12; iIndex++)
		{
			isGeneralVar -= g_acNumOfDaysPerMonth[iIndex];
			if (isGeneralVar < 0)
					break;
		}
		if(iIndex == 12)
		{ // TODO: this is from the getTime application. Why is it here? This cannot occur
			iIndex = 0;
		}
		iIndex++;
		if(iIndex < 10)
		{
			memcpy(pcCCPtr, "0", 1);
			pcCCPtr++;
		}
		uisCCLen = itoa(iIndex, pcCCPtr);
		pcCCPtr += uisCCLen;

		// date
		// restore the day in current month
		isGeneralVar += g_acNumOfDaysPerMonth[iIndex-1];
		if(isGeneralVar + 1 < 10)
		{
			memcpy(pcCCPtr, "0", 1);
			pcCCPtr++;
		}
		uisCCLen = itoa(isGeneralVar + 1, pcCCPtr);
		pcCCPtr += uisCCLen;
		*pcCCPtr++ = 'T';

		// time
		ulGeneralVar = ulElapsedSec%SEC_IN_DAY;

		// number of seconds per hour
		ulGeneralVar1 = ulGeneralVar%SEC_IN_HOUR;

		// number of hours
		ulGeneralVar /= SEC_IN_HOUR;
		if(ulGeneralVar < 10)
		{
			memcpy(pcCCPtr, "0", 1);
			pcCCPtr++;
		}
		uisCCLen = itoa(ulGeneralVar, pcCCPtr);
		pcCCPtr += uisCCLen;

		// number of minutes per hour
		ulGeneralVar = ulGeneralVar1/SEC_IN_MIN;
		if(ulGeneralVar < 10)
		{
			memcpy(pcCCPtr, "0", 1);
			pcCCPtr++;
		}
		uisCCLen = itoa(ulGeneralVar, pcCCPtr);
		pcCCPtr += uisCCLen;

		// number of seconds per minute
		ulGeneralVar1 %= SEC_IN_MIN;
		if(ulGeneralVar1 < 10)
		{
			memcpy(pcCCPtr, "0", 1);
			pcCCPtr++;
		}
		uisCCLen = itoa(ulGeneralVar1, pcCCPtr);
		pcCCPtr += uisCCLen;
		*pcCCPtr++ = 'Z';

		// Terminate the string
		*pcCCPtr++ = '\0';

		strcpy(pcResult, acTimeStore);


    }
    return SUCCESS;
}

//*****************************************************************************
//
//! SHAMD5IntHandler - Interrupt Handler which handles different interrupts from
//! different sources
//!
//! \param None
//!
//! \return None
//
//*****************************************************************************
void
SHAMD5IntHandler(void)
{
    uint32_t ui32IntStatus;
    //
    // Read the SHA/MD5 masked interrupt status.
    //
    ui32IntStatus = MAP_SHAMD5IntStatus(SHAMD5_BASE, true);
    if(ui32IntStatus & SHAMD5_INT_CONTEXT_READY)
    {
        MAP_SHAMD5IntDisable(SHAMD5_BASE, SHAMD5_INT_CONTEXT_READY);
        g_bContextReadyFlag = true;

    }
    if(ui32IntStatus & SHAMD5_INT_PARTHASH_READY)
    {
        MAP_SHAMD5IntDisable(SHAMD5_BASE, SHAMD5_INT_PARTHASH_READY);
        g_bParthashReadyFlag=true;

    }
    if(ui32IntStatus & SHAMD5_INT_INPUT_READY)
    {
        MAP_SHAMD5IntDisable(SHAMD5_BASE, SHAMD5_INT_INPUT_READY);
        g_bInputReadyFlag = true;

    }
    if(ui32IntStatus & SHAMD5_INT_OUTPUT_READY)
    {
        MAP_SHAMD5IntDisable(SHAMD5_BASE, SHAMD5_INT_OUTPUT_READY);
        g_bOutputReadyFlag = true;

    }

}

//*****************************************************************************
//
//! Generates an HMAC SHA256 Signature for the publish
//!
//! \brief  This generates the authentication signature, required for SNS.
//!
//! \param  pcResult is a pointer to where the signature will be stored.
//! \param  pcDatetime is a pointer to a datetime string of the format YYYYMMDD'T'HHMMSS'Z'
//!           For example: "20150117T215403Z"
//! \param  pcDate is a pointer to a date string of the format YYYYMMDD
//!
//! \return none
//!
//
//*****************************************************************************
void GenerateSignature(char * pcResult, char *pcDatetime, char *pcDate)
{
	char *pcHashKey, *pcHashData, *pcHashResult;
	char acHashKey[64], acHashData[512], acHashResult[32], acHexString[65];
	unsigned int uiDataLength;
	unsigned int uiPointerOffset;
	unsigned int ui8count;  // TODO: remove with debug code

	pcHashKey = acHashKey;  //TODO: why make pcHashKey a variable, when acKey does the same thing anyway?
	pcHashData = acHashData;
	pcHashResult = acHashResult;

	// Enable the module .
	MAP_PRCMPeripheralClkEnable(PRCM_DTHE, PRCM_RUN_MODE_CLK);
	// Enable interrupts.
	MAP_SHAMD5IntRegister(SHAMD5_BASE, SHAMD5IntHandler);

	// Reset the module
	MAP_PRCMPeripheralReset(PRCM_DTHE);
	// Clear the flags
	g_bContextReadyFlag = false;
	g_bInputReadyFlag = false;
	// Enable interrupts.
	MAP_SHAMD5IntEnable(SHAMD5_BASE, SHAMD5_INT_CONTEXT_READY |
					SHAMD5_INT_PARTHASH_READY |
					SHAMD5_INT_INPUT_READY |
					SHAMD5_INT_OUTPUT_READY);
	// Wait for the context ready flag.
	while(!g_bContextReadyFlag)
	{
	}

	//
	// Generate the Derived Signing Key
	// TODO: make this into a separate function

	// Configure the SHA/MD5 module for HMAC_SHA256
	MAP_SHAMD5ConfigSet(SHAMD5_BASE, SHAMD5_ALGO_HMAC_SHA256);
	// Create the Signature Key
	strcpy(pcHashKey, SECRET_KEY_PREFIX);
	strcpy(pcHashKey+strlen(SECRET_KEY_PREFIX), SNS_SECRET_KEY);
	uiPointerOffset = strlen(SNS_SECRET_KEY)+strlen(SECRET_KEY_PREFIX);
	memset(pcHashKey+uiPointerOffset, 0, 64-uiPointerOffset);
	strcpy(pcHashData, pcDate);
	uiDataLength = strlen(pcDate);
	MAP_SHAMD5HMACKeySet(SHAMD5_BASE, pcHashKey);
	MAP_SHAMD5HMACProcess(SHAMD5_BASE, pcHashData, uiDataLength, pcHashResult);

	memcpy(pcHashKey, pcHashResult, 32);
	memset(pcHashKey+32, 0, 32);
	strcpy(pcHashData, SNS_REGION);
	uiDataLength = strlen(SNS_REGION);
	MAP_SHAMD5HMACKeySet(SHAMD5_BASE, pcHashKey);
	MAP_SHAMD5HMACProcess(SHAMD5_BASE, pcHashData, uiDataLength, pcHashResult);

	memcpy(pcHashKey, pcHashResult, 32);
	memset(pcHashKey+32, 0, 32);
	strcpy(pcHashData, SNS_SERVICE);
	uiDataLength = strlen(SNS_SERVICE);
	MAP_SHAMD5HMACKeySet(SHAMD5_BASE, pcHashKey);
	MAP_SHAMD5HMACProcess(SHAMD5_BASE, pcHashData, uiDataLength, pcHashResult);

	memcpy(pcHashKey, pcHashResult, 32);
	memset(pcHashKey+32, 0, 32);
	strcpy(pcHashData, SNS_REQUEST_KEY);
	uiDataLength = strlen(SNS_REQUEST_KEY);
	MAP_SHAMD5HMACKeySet(SHAMD5_BASE, pcHashKey);
	MAP_SHAMD5HMACProcess(SHAMD5_BASE, pcHashData, uiDataLength, pcHashResult);
	memcpy(pcHashKey, pcHashResult, 32);
	memset(pcHashKey+32, 0, 32);

	// pcHashKey now contains the Derived Signing Key

	//
	// Generate the String-To-Sign
	// TODO: make this into a separate function
	//

	// Configure the SHA/MD5 module for SHA256 (non-HMAC)
	MAP_SHAMD5ConfigSet(SHAMD5_BASE, SHAMD5_ALGO_SHA256);

	// Create the hash of the payload, for the canonical string
	strcpy(pcHashData, REQUEST_PAYLOAD_PREFIX);
	uiDataLength = strlen(REQUEST_PAYLOAD_PREFIX);
	strcpy((pcHashData + uiDataLength), SNS_TOPIC_ONE);
	uiDataLength += strlen(SNS_TOPIC_ONE);
	strcpy((pcHashData + uiDataLength), REQUEST_PAYLOAD_SUFFIX);
	uiDataLength += strlen(REQUEST_PAYLOAD_SUFFIX);
	MAP_SHAMD5DataProcess(SHAMD5_BASE, pcHashData, uiDataLength, pcHashResult);

	// Build the Canonical String
	strcpy(pcHashData, CANONIC_REQUEST_PREFIX);
	uiDataLength = strlen(CANONIC_REQUEST_PREFIX);
	strcpy((pcHashData + uiDataLength), pcDatetime);
	uiDataLength += strlen(pcDatetime);
	strcpy((pcHashData + uiDataLength), CANONIC_REQUEST_SUFFIX);
	uiDataLength += strlen(CANONIC_REQUEST_SUFFIX);
	HexToString(pcHashResult, 32, acHexString);
	strcpy((pcHashData + uiDataLength), acHexString); // Add the hex-encoded hash of the payload
	uiDataLength += strlen(acHexString);

	// pcHashData now contains the complete Canonical Request String
	UART_PRINT("Canonical String:\r\n'%s'\r\n\r\n", pcHashData);

	// Create a digest (hash) of the Canonical String.
	// This digest will be used later in the Sting-To-Sign.
	MAP_SHAMD5DataProcess(SHAMD5_BASE, pcHashData, uiDataLength, pcHashResult);
	UART_PRINT("Canonical Hash: '");
	for(ui8count=0; ui8count<32; ui8count++)
	{
		UART_PRINT("%02x", *(pcHashResult + ui8count));
	}
	UART_PRINT("'\r\n\r\n");

	// pcHashResult now contains the hash of the Canonical String

	memset(acHashData, 0xA5, sizeof(acHashData));

	// Create the String-To-Sign
	strcpy(pcHashData, STRING_TO_SIGN_ALGO);
	uiDataLength = strlen(STRING_TO_SIGN_ALGO);
	strcpy((pcHashData + uiDataLength), pcDatetime);
	uiDataLength += strlen(pcDatetime);
	strcpy((pcHashData + uiDataLength), "\n");
	uiDataLength++;
	strcpy((pcHashData + uiDataLength), pcDate);
	uiDataLength += strlen(pcDate);
	strcpy((pcHashData + uiDataLength), STRING_TO_SIGN_SCOPE);
	uiDataLength += strlen(STRING_TO_SIGN_SCOPE);
	HexToString(pcHashResult, 32, acHexString);
	strcpy((pcHashData + uiDataLength), acHexString); // Add the hex-encoded hash of the Canonical String
	uiDataLength += strlen(acHexString);

	// pcHashData now contains the complete String-To-Sign


	UART_PRINT("String to sign:\r\n'%s'\r\n\r\n", pcHashData);
	UART_PRINT("Signing key: '");
	for(ui8count=0; ui8count<32; ui8count++)
	{
		UART_PRINT("%02x", *(pcHashKey + ui8count));
	}
	UART_PRINT("'\r\n\r\n");


	//
	// Compute the final Signature
	// TODO: Make this into a separate function
	//

	// Configure the SHA/MD5 module for HMAC_SHA256
	MAP_SHAMD5ConfigSet(SHAMD5_BASE, SHAMD5_ALGO_HMAC_SHA256);

	MAP_SHAMD5HMACKeySet(SHAMD5_BASE, pcHashKey);
	MAP_SHAMD5HMACProcess(SHAMD5_BASE, pcHashData, uiDataLength, pcHashResult);

	HexToString(pcHashResult, 32, pcResult);
}

//*****************************************************************************
//
//! Converts a numeric hexidecimal value to a string.
//!
//! \brief  Converts a numeric hexidecimal value to a string.
//!
//! \param  pcHex is a pointer to the original hex value we will be converting
//! \param  uiHexLength is the number of bytes in the hex value
//! \param  pcConveredString is a pointer to where we will store the converted string
//!           The allocated space should be at least uiHexLength*2 chars long
//!
//! \return none
//!
//
//*****************************************************************************
void HexToString(char * pcHex, unsigned int uiHexLength, char * pcConvertedString)
{
	unsigned int uiCount;

	// Each byte (char) in pcHex contains two characters
	// For example, the byte 0x00111010 becomes "3A"
	for(uiCount=0; uiCount<uiHexLength; uiCount++)
	{
		// Extract the character from the upper (left) nibble
		*(pcConvertedString + uiCount*2) = HexNibbleToChar(*(pcHex + uiCount) >> 4);

		// Extract the character from the lower (right) nibble
		*(pcConvertedString + uiCount*2 + 1) = HexNibbleToChar(*(pcHex + uiCount) & 0x0f);
	}
	*(pcConvertedString + uiHexLength*2) = (char)0;
}

//*****************************************************************************
//
//! Converts a single hexidecimal nibble (4 bits) to a string.
//!
//! \brief  Converts a single hexidecimal nibble (4 bits) to a string.
//!
//! \param  uiHexNibble is the 4-bit hex value we will convert.
//!
//! \return The character which represents the input nibble.
//!
//
//*****************************************************************************
char HexNibbleToChar(unsigned int uiHexNibble)
{
	char cHexChar;

	// "0" to "9" are ASCII values 0x30 to 0x39
	if(uiHexNibble <= 0x9)
	{
		cHexChar = (char)(uiHexNibble + 0x30);
	}
	// "a" to "f" are ASCII values 0x61 to 0x66
	else if((uiHexNibble >= 0xa) && (uiHexNibble <= 0xf))
	{
		cHexChar = (char)(uiHexNibble + 0x57);
	}
	else
	{
		cHexChar = "_";
		UART_PRINT("Failed to convert hex \"%x\" to string.", uiHexNibble);
	}

	return cHexChar;
}

//*****************************************************************************
//
//! Sends an HTTP POST message to the Amazon SNS server
//!
//! \brief  This function sends an HTTP POST message to the Amazon SNS server.
//!
//! \param  iSockID is the socket ID
//!
//! \return 0 if success
//!
//
//*****************************************************************************
long POSTToSNS(int iSockID, char *pcSNSTopic)
{
	int iTXStatus;
	int iRXDataStatus;
	unsigned int uiPayloadSize, uiContentLengthArraySize;
	char acPayloadLength[8];
	char acSendBuffer[768];
	char acRecvBuffer[1460];
	char *pcBufLocation;
	char acSignature[64];
	char acDatetime[17], acDate[9];

	// Get the current datetime
	GetDatetime(acDatetime);
	memcpy(acDate, acDatetime, 8);
	acDate[8] = '\0';

	memset(acRecvBuffer, 0, sizeof(acRecvBuffer));

	// Put together the http POST string
	pcBufLocation = acSendBuffer;
	strcpy(pcBufLocation, REQUEST_PREFIX);
	pcBufLocation += strlen(REQUEST_PREFIX);
	uiPayloadSize = strlen(REQUEST_PAYLOAD_PREFIX);
	uiPayloadSize += strlen(SNS_TOPIC_ONE);
	uiPayloadSize += strlen(REQUEST_PAYLOAD_SUFFIX);
	uiContentLengthArraySize = itoa(uiPayloadSize, acPayloadLength);
	memcpy(pcBufLocation, acPayloadLength, uiContentLengthArraySize);
	pcBufLocation += uiContentLengthArraySize;
	strcpy(pcBufLocation, "\n");
	pcBufLocation ++;
	strcpy(pcBufLocation, REQUEST_DATE_HEADER);
	pcBufLocation += strlen(REQUEST_DATE_HEADER);
	strcpy(pcBufLocation, acDatetime);
	pcBufLocation += strlen(acDatetime);
	strcpy(pcBufLocation, "\n");
	pcBufLocation ++;
	strcpy(pcBufLocation, REQUEST_AUTH_HEADER);
	pcBufLocation += strlen(REQUEST_AUTH_HEADER);
	strcpy(pcBufLocation, SNS_ACCESS_KEY);
	pcBufLocation += strlen(SNS_ACCESS_KEY);
	strcpy(pcBufLocation, "/");
	pcBufLocation ++;
	strcpy(pcBufLocation, acDate);
	pcBufLocation += strlen(acDate);
	strcpy(pcBufLocation, REQUEST_AUTH_SUFFIX);
	pcBufLocation += strlen(REQUEST_AUTH_SUFFIX);

	GenerateSignature(acSignature, acDatetime, acDate);
//	UART_PRINT("Generated signature: ");
//	for(uiCount=0; uiCount<64; uiCount++)
//	{
//		UART_PRINT("%c", acSignature[uiCount]);
//	}
//	UART_PRINT("\r\n");
	strcpy(pcBufLocation, acSignature);
	pcBufLocation += 64;
	strcpy(pcBufLocation, REQUEST_PREPAYLOAD);
	pcBufLocation += strlen(REQUEST_PREPAYLOAD);
	strcpy(pcBufLocation, REQUEST_PAYLOAD_PREFIX);
	pcBufLocation += strlen(REQUEST_PAYLOAD_PREFIX);
	strcpy(pcBufLocation, pcSNSTopic);
	pcBufLocation += strlen(pcSNSTopic);
	strcpy(pcBufLocation, REQUEST_PAYLOAD_SUFFIX);
	pcBufLocation += strlen(REQUEST_PAYLOAD_SUFFIX);

//	UART_PRINT("acSendBuffer length %i\r\n", strlen(acSendBuffer));
	UART_PRINT("POST string:\r\n");
	UART_PRINT("'%s'\r\n\r\n", acSendBuffer);

	//
	// Send the HTTP POST string to the open TCP/IP socket.
	//
	iTXStatus = sl_Send(iSockID, acSendBuffer, strlen(acSendBuffer), 0);
	if(iTXStatus < 0)
	{
		DBG_PRINT("Error sending POST request\n\r");
		ASSERT_ON_ERROR(-1);
	}
	else
	{
		DBG_PRINT("Sent HTTP POST request. \n\r");
	}

	DBG_PRINT("Return value: %d \n\r", iTXStatus);

	//
	// Store the reply from the server in buffer.
	//
	iRXDataStatus = sl_Recv(iSockID, &acRecvBuffer[0], sizeof(acRecvBuffer), 0);
	if(iRXDataStatus < 0)
	{
		DBG_PRINT("Error receiving response\n\r");
		ASSERT_ON_ERROR(-1);
	}
	else
	{
		DBG_PRINT("Received HTTP POST response data. \n\r");
	}

	DBG_PRINT("Return value: %d \n\r", iRXDataStatus);
	DBG_PRINT("Response: %s", &acRecvBuffer);


	return SUCCESS;
}

//*****************************************************************************
//
//! Periodic Timer Interrupt Handler
//!
//! \param None
//!
//! \return None
//
//*****************************************************************************
void
TimerPeriodicIntHandler(void)
{
    unsigned long ulInts;

    //
    // Clear all pending interrupts from the timer we are
    // currently using.
    //
    ulInts = MAP_TimerIntStatus(TIMERA0_BASE, true);
    MAP_TimerIntClear(TIMERA0_BASE, ulInts);

    //
    // Increment our interrupt counter.
    //
    g_usTimerInts++;
    if(!(g_usTimerInts & 0x1))
    {
        //
        // Off Led
        //
        GPIO_IF_LedOff(MCU_RED_LED_GPIO);
    }
    else
    {
        //
        // On Led
        //
        GPIO_IF_LedOn(MCU_RED_LED_GPIO);
    }
}

//****************************************************************************
//
//! Function to configure and start timer to blink the LED while device is
//! trying to connect to an AP
//!
//! \param none
//!
//! return none
//
//****************************************************************************
void LedTimerConfigNStart()
{
    //
    // Configure Timer for blinking the LED for IP acquisition
    //
    Timer_IF_Init(PRCM_TIMERA0,TIMERA0_BASE,TIMER_CFG_PERIODIC,TIMER_A,0);
    Timer_IF_IntSetup(TIMERA0_BASE,TIMER_A,TimerPeriodicIntHandler);
    Timer_IF_Start(TIMERA0_BASE,TIMER_A,PERIODIC_TEST_CYCLES / 10);
}

//****************************************************************************
//
//! Disable the LED blinking Timer as Device is connected to AP
//!
//! \param none
//!
//! return none
//
//****************************************************************************
void LedTimerDeinitStop()
{
    //
    // Disable the LED blinking Timer as Device is connected to AP
    //
    Timer_IF_Stop(TIMERA0_BASE,TIMER_A);
    Timer_IF_DeInit(TIMERA0_BASE,TIMER_A);

}

//****************************************************************************
//
//! Task function implementing the gettime functionality using an NTP server
//!
//! \param none
//!
//! This function
//!    1. Initializes the required peripherals
//!    2. Initializes network driver and connects to the default AP
//!    3. Creates a UDP socket, gets the NTP server IP address using DNS
//!    4. Periodically gets the NTP time and displays the time
//!
//! \return None.
//
//****************************************************************************
void MonitorWasherTask(void *pvParameters)
{
    long lRetVal = -1;
    char acTopicARN[64];

    UART_PRINT("Washer Alert: Test Begin\n\r");

//    // Test code for hash function
//    unsigned int ui8count;
//    unsigned char *puiResult;
//	unsigned char acResult[64];
//    puiResult = acResult;
//    GenerateSignature(puiResult);
//    UART_PRINT("Signature: ");
//	for(ui8count=0; ui8count<64; ui8count++)
//	{
//		UART_PRINT("%c", *(puiResult + ui8count));
//	}
//	UART_PRINT("\r\n\r\n");
//	// End of test code

    //
    // Configure LED
    //
    GPIO_IF_LedConfigure(LED1|LED2|LED3);

    GPIO_IF_LedOff(MCU_RED_LED_GPIO);
    GPIO_IF_LedOff(MCU_ORANGE_LED_GPIO);
    GPIO_IF_LedOff(MCU_GREEN_LED_GPIO);

    // Configure Button Interrupts
    SetupButtonInterrupts();

    //
    // Reset The state of the machine
    //
    Network_IF_ResetMCUStateMachine();

    while(1){};

    while(1)
    {
		WaitForStart();
		WaitForFinish();

		//
		// Start the driver
		//
		lRetVal = Network_IF_InitDriver(ROLE_STA);
		if(lRetVal < 0)
		{
		   UART_PRINT("Failed to start SimpleLink Device\n\r",lRetVal);
		   LOOP_FOREVER();
		}

		// switch on Green LED to indicate Simplelink is properly up
		GPIO_IF_LedOn(MCU_ON_IND);

		// Start Timer to blink Red LED till AP connection
		LedTimerConfigNStart();

		// Initialize AP security params
		SecurityParams.Key = (signed char *)SECURITY_KEY;
		SecurityParams.KeyLen = strlen(SECURITY_KEY);
		SecurityParams.Type = SECURITY_TYPE;

		//
		// Connect to the Access Point
		//
		lRetVal = Network_IF_ConnectAP(SSID_NAME, SecurityParams);
		// TODO: Network_IF_ConnectAP has a function to handle a failure to connect,
		//			but the program halts if it enters that loop
		if(lRetVal < 0)
		{
		   UART_PRINT("Connection to an AP failed\n\r");
		   LOOP_FOREVER();
		}

		//
		// Disable the LED blinking Timer as Device is connected to AP
		//
		LedTimerDeinitStop();

		//
		// Switch ON RED LED to indicate that Device acquired an IP
		//
		GPIO_IF_LedOn(MCU_IP_ALLOC_IND);


		strcpy(acTopicARN, SNS_TOPIC_ONE);  // TODO: split for multiple topicARN's
		PublishSNS(acTopicARN);


//end: // TODO: why is this "end" line here?

		//
		// Stop the driver
		//
		lRetVal = Network_IF_DeInitDriver();
		if(lRetVal < 0)
		{
		   UART_PRINT("Failed to stop SimpleLink Device\n\r");
		   LOOP_FOREVER();
		}
    }

    //
    // Switch Off RED & Green LEDs to indicate that Device is
    // disconnected from AP and Simplelink is shutdown
    //
    GPIO_IF_LedOff(MCU_IP_ALLOC_IND);
    GPIO_IF_LedOff(MCU_GREEN_LED_GPIO);

    UART_PRINT("Washer Alert: Test Complete\n\r");

    //
    // Loop here
    //
    LOOP_FOREVER();
}

//*****************************************************************************
//
//! Application startup display on UART
//!
//! \param  none
//!
//! \return none
//!
//*****************************************************************************
static void
DisplayBanner(char * AppName)
{

    UART_PRINT("\n\n\n\r");
    UART_PRINT("\t\t *************************************************\n\r");
    UART_PRINT("\t\t      CC3200 %s Application       \n\r", AppName);
    UART_PRINT("\t\t *************************************************\n\r");
    UART_PRINT("\n\n\n\r");
}

void SetupButtonInterrupts()
{
	// Setup SW3
	MAP_GPIOIntTypeSet(GPIOA1_BASE, GPIO_PIN_5, GPIO_FALLING_EDGE);
	osi_InterruptRegister(INT_GPIOA1, (P_OSI_INTR_ENTRY)SW3InterruptHandler, INT_PRIORITY_LVL_1);
	MAP_GPIOIntClear(GPIOA1_BASE, GPIO_PIN_5);
	MAP_GPIOIntEnable(GPIOA1_BASE, GPIO_INT_PIN_5);

	// Setup SW2
	MAP_GPIOIntTypeSet(GPIOA2_BASE, GPIO_PIN_6, GPIO_FALLING_EDGE);
	osi_InterruptRegister(INT_GPIOA2, (P_OSI_INTR_ENTRY)SW2InterruptHandler, INT_PRIORITY_LVL_1);
	MAP_GPIOIntClear(GPIOA2_BASE, GPIO_PIN_6);
	MAP_GPIOIntEnable(GPIOA2_BASE, GPIO_INT_PIN_6);
}

//*****************************************************************************
//
//! Interrupt Handler for SW2
//!
//! \param  none
//!
//! \return none
//!
//*****************************************************************************
void SW2InterruptHandler()
{
	unsigned long ulPinState = GPIOIntStatus(GPIOA2_BASE, true);
	if(ulPinState & GPIO_PIN_6)
	{
		// Start the interrupt routine
		GPIO_IF_LedToggle(MCU_RED_LED_GPIO);
		MAP_UtilsDelay(SLEEP_TIME/20);

		// Clear the interrupt flag
		MAP_GPIOIntClear(GPIOA2_BASE, GPIO_PIN_6);
	}
}

//*****************************************************************************
//
//! Interrupt Handler for SW3
//!
//! \param  none
//!
//! \return none
//!
//*****************************************************************************
void SW3InterruptHandler()
{
	unsigned long ulPinState = GPIOIntStatus(GPIOA1_BASE, true);
	if(ulPinState & GPIO_PIN_5)
	{
		// Start the interrupt routine
		GPIO_IF_LedToggle(MCU_GREEN_LED_GPIO);
		MAP_UtilsDelay(SLEEP_TIME/20);

		// Clear the interrupt flag
		MAP_GPIOIntClear(GPIOA1_BASE, GPIO_PIN_5);
	}
}

//*****************************************************************************
//
//! Board Initialization & Configuration
//!
//! \param  None
//!
//! \return None
//
//*****************************************************************************
static void
BoardInit(void)
{
/* In case of TI-RTOS vector table is initialize by OS itself */
#ifndef USE_TIRTOS

    //
    // Set vector table base
    //
#if defined(ccs) || defined(gcc)
    MAP_IntVTableBaseSet((unsigned long)&g_pfnVectors[0]);
#endif
#if defined(ewarm)
    MAP_IntVTableBaseSet((unsigned long)&__vector_table);
#endif
#endif

    //
    // Enable Processor
    //
    MAP_IntMasterEnable();
    MAP_IntEnable(FAULT_SYSTICK);

    PRCMCC3200MCUInit();
}

//****************************************************************************
//
//! Main function
//!
//! \param none
//!
//! This function
//!    1. Invokes the SLHost task
//!    2. Invokes the GetNTPTimeTask
//!
//! \return None.
//
//****************************************************************************
void main()
{
    long lRetVal = -1;

    //
    // Initialize Board configurations
    //
    BoardInit();

    //
    // Enable and configure DMA
    //
    UDMAInit();

    //
    // Pinmux for UART
    //
    PinMuxConfig();

    //
    // Configuring UART
    //
    InitTerm();

    //
    // Display Application Banner
    //
    DisplayBanner(APP_NAME);

    //
    // Start the SimpleLink Host
    //
    lRetVal = VStartSimpleLinkSpawnTask(SPAWN_TASK_PRIORITY);
    if(lRetVal < 0)
    {
        ERR_PRINT(lRetVal);
        LOOP_FOREVER();
    }

    //
    // Start the Monitor Washer task
    //
    lRetVal = osi_TaskCreate(MonitorWasherTask,
                    (const signed char *)"Monitor Washer",
                    OSI_STACK_SIZE,
                    NULL,
                    1,
                    NULL );

    if(lRetVal < 0)
    {
        ERR_PRINT(lRetVal);
        LOOP_FOREVER();
    }

    //
    // Start the task scheduler
    //
    osi_start();
}

//*****************************************************************************
//
// Close the Doxygen group.
//! @}
//
//*****************************************************************************
