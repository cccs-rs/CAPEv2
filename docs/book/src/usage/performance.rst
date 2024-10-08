===========
Performance
===========

There are several ways to tune the CAPE performance

Processing
==========

"Processing" consists of three steps after the malware is executed in a VM. Those are

* processing of raw data
* signature matching
* reporting

Processing can take up to 30 minutes if the original raw log is large. This is caused by many API calls in that log. Several
steps will iterate through that API list which causes a slowdown. There are several ways to mitigate the impact:

Evented signatures
------------------

Evented signatures have a common loop through the API calls. Use them wherever possible and either switch the
old-style signatures with their api-call loop or convert them to event based signatures

Reporting
---------

Reports that contain the API log will also iterate through the list. De-activate reports you do not need.
For automated environments switching off the html report will be a good choice.

Ram-boost
---------

Ram boost can be switched on in the configuration (in *conf/cuckoo.conf* ``ram_boost`` in ``[processing]``).
This will keep the whole API list in Ram. Do that only if you have plenty of Ram (>20 GB for 8 VMs).
