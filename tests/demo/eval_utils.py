import json

def get_state_stats(s):
    stats = {}
    stats['num_constraints'] = len(s.solver.constraints)

    csts = s.solver.constraints
    stats['cst_depths'] = [c.depth for c in csts]
    stats['num_leaves'] = [len(list(c.recursive_leaf_asts)) for c in csts]
    return stats

def dump_state_stats(s):
    print json.dumps(get_state_stats(s))
    return
    print "Number of constraints: {}".format(len(s.solver.constraints))
    csts = s.solver.constraints
    print "Constraint depths: {}".format([c.depth for c in csts])
    print "Number of leaf ASTS: {}".format([len(list(c.recursive_leaf_asts)) for c in csts])

def dump_sm_stats(sm):
    for stash, states in sm.stashes.iteritems():
        if not states:
            continue
        print stash
        for s in states:
            print json.dumps(get_state_stats(s))
            
