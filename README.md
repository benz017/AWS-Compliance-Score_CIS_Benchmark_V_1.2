# AWS-Compliance-Score_CIS_Benchmark_V_1.2

=== Description ===

This code is build as per the CIS Amazon Web Services Foundations, check for the detailed pdf above.
The above code takes a JSON string as an input and gives a response of the current values of the parameters set in your AWS account to verify it's compliance.
It also gives you a compliance score based on the number of Controls sent to the input JSON to the score aquired by the compliant controls(Scored/Not Scored). Scored and Not Scored are binary tags given to each controls as per their priority, Scored being higher priority than Not Scored.
Total Compliance Score = ((Compliant Scored controls + Compliant Not-Scored controls)/Total No. of Controls)*100 %
Hence, giving us a pretty accurate idea of our cloud infrastructure compliance and hence making the necessary changes to remediate on them further.

=== Set Up ===

1. Install the packages in the requirements.txt for the script to work

2. In the file AWS-Compliance-Score_CIS_Benchmark_V_1.2.py replace the << CloudAccessKey >>, << CloudSecretKey >> and << CloudRegion >> with your AWS Access Key, AWS Secret Access Key and Region in order to connect the script to your AWS account.

3. A JSON string as per the inputJSONTemplate.txt file needs to be inserted in place of << INPUT JSON >> with reference to the CISControlList.txt which has all the mappings accordingly.

4. The file responseJSONtemplate.txt has the output response on execution of the script. It will also provide the Compliance Score below.
=======================================================
============= COMPLIANCE SCORE : X% ================
=======================================================
