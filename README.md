# pdb

This repository contains a script which utilised pdb to provide useful functions.


GET STARTED:

Copy example.pdb.yaml into ~/.pdb/pdb.yaml and modify accordingly

FACT QUERIES:

The -f, --fact argument supports many different formats

You can use it to simply include a fact in the output:

-f osfamily

You can use it to specify criteria to filter results:
-f osfamily=RedHat
OR:
-f osfamily~RedHat
OR:
-f 'memorysize_mb<1000'

This script supports all the operators available in the v3 puppetdb API (=,~,<,>,<=,>=).

You can specify either multiple -f arguments or a single -f with comma-separated options
-f osfamily -f selinux_enforced
is the same as:
-f osfamily,selinux_enforced

You can mix and match options:
-f 'osfamily,memorysize_mb<1000'
This will include the osfamily fact in the output and select nodes where the memorysize_mb fact is less than 1000

