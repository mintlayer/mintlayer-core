## Fork detection script, for the extra peace of mind

Here we have `detector.py`, which is a relatively crude way of detecting a permanent fork (split)
in the network if it happens.

The script basically runs the full sync in a loop, checking the node's log output for certain errors
and comparing its mainchain block ids with those obtained from the API server.\
If anything suspicious is detected during the full sync, the script will save the node's data
directory and log file.\
In any case, the script will temporarily ban some of the peers that participated in the sync
(so that the next iteration has a chance to have different ones and to reduce the strain on
the network) and start the full sync all over again, reusing the peerdb from the previous iteration.

The node is always run with checkpoints disabled, so that it has the chance to find older forks too.

The structure of the script's working directory (specified via the command line):
- `current_attempt` - this corresponds to the current sync attempt (iteration).
- `saved_attempts` - this contains subdirectories corresponding to attempts that
  are considered suspicious; each subdirectory's name is the datetime of the moment
  when the attempt was finished.
- `saved_peer_dbs` - this is where peer dbs from previous attempts are stored; the script
  only needs the one from the latest attempt, but, just in case, the penultimate one is
  also stored.
- `log.txt` - this is the log of the script itself.

Each attempt's directory has the following structure:
- `flags` - this directory contains flag files (which are usually zero-length) indicating
  that certain problems were found during the sync. It is what determines whether the attempt's
  directory will be saved in the end (i.e. if the directory is non-empty, the attempt will be saved).
- `node_data` - this is the node's data directory of this attempt.
- `node_log.txt` - the node's log.

Note: currently the script requires Python 3.13 to run, though we may lift this requirement later.
