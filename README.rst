<p align="center"><img src="https://raw.githubusercontent.com/someengineering/cloudkeeper/main/misc/cloudkeeper_200.png" /><h1 align="center">Cloudkeeper</h1></p>

Cloudkeeper
===========

Getting started
---------------
Cloudkeeper is “housekeeping for clouds” - find leaky resources, manage quota limits, detect drift and clean up. 

Infrastructure management tools like Terraform and CloudFormation do a good job at managing resources they know about. But they do a poor job at managing resources they did not create. 

You can see drift in your environment, but only if the tool itself created the left-behind artifacts. The unknown drift makes it hard for developers and engineers to discover, understand and take action on resources. 
Cloudkeeper fixes that gap in your environment.

Quick start
-----------
In this quick start guide, we’re showing you three things, how to:

    #. install Cloudkeeper for AWS with docker
    #. use the Cloudkeeper CLI to run your first ``collect`` process
    #. query the results of the collect process 

The docker set-up takes 2-5 minutes. The duration of the first collect process depends on the size of your environment - usually 2-5 minutes. 

| Examples and data in this documentation are based on a small AWS `cloud9 <https://aws.amazon.com/cloud9/>`_ environment.
| To start exploring you need AWS credentials and a working docker environment with access to AWS APIs.
| We assume you are familiar with basic docker operations and how to operate a linux shell.You find our current Documentation over here:


--> `Continue reading your Quick start tutorial <https://docs.some.engineering>`_


| *Reach out to us if you have any questions, improvements, bugs!*
| *Contributions are very much appreciated.*


| *Discord:*
| https://discord.gg/3G3sX6y3bt


| *GitHub Issue:*
| https://github.com/someengineering/cloudkeeper/issues/new 