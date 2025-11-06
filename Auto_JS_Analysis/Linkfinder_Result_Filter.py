with open("linkfinder_result.txt") as f:
    urls = []
    paths = []
    for line in f:
        line = line.strip()
        if not line:
            continue
        if line.startswith(("http://", "https://", "//")):
            urls.append(line)
        else:
            if not line.startswith("/"):
                line = "/" + line
            paths.append(line)

with open("full_urls.txt", "w") as f:
    f.write("\n".join(sorted(set(urls))) + "\n")

with open("paths.txt", "w") as f:
    f.write("\n".join(sorted(set(paths))) + "\n")
