This project is in its early stages. Most of the functionality does not work.

Much of this project is derived from CC3200 examples published by Texas Instruments.
The examples are available on the TI wiki: http://processors.wiki.ti.com/index.php/CC32xx_SDK_Sample_Applications

The project requires a file names "auth.h" which contains some authentication parameters for Amazon AWS.
The file should be of the format:

#define SNS_TOPIC_ONE		"TOPIC_ONE_ARN"
#define SNS_TOPIC_TWO		"TOPIC_TWO_ARN"

#define SNS_ACCESS_KEY		"YOUR_AWS_ACCESS_KEY"
#define SNS_SECRET_KEY		"YOUR_AWS_SECRET_KEY"