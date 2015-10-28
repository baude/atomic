% ATOMIC(1) Atomic Man Pages
% Brent Baude
% Novemeber 2015
# NAME
atomic-restart - Restart a container which has been run or created with atomic
# SYNOPSIS
**atomic restart**
[**-h**|**--help**]
CONTAINER ]

# DESCRIPTION
**atomic restart** will restart a running container as long as it has been run with atomic. It can take a container ID, container name, or an image name as input.

# OPTIONS
**-h** **--help**
  Print usage statement

# EXAMPLES
Restart a container by its container ID.

    atomic restart 453980ba5ab1

Restart the rsyslog container by calling its image name.

    atomic restart registry.access.redhat.com/rhel7/rsyslog

# HISTORY
Initial revision by Brent Baude (bbaude at redhat dot com) November 2015
