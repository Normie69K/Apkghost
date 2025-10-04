# Example plugin: analyze strings for "TODO" comments
def run(project_path):
    findings = []
    import os
    for root, _, files in os.walk(project_path):
        for f in files:
            if f.endswith(('.java','.smali','.xml')):
                p = os.path.join(root,f)
                try:
                    with open(p,'r',errors='ignore') as fh:
                        for i,l in enumerate(fh,1):
                            if "TODO" in l:
                                findings.append({'file':p,'line':i,'text':l.strip()})
                except: pass
    return findings
