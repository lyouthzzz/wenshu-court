import re
url = 'http://wenshu.court.gov.cn/content/content?DocID=465f975a-e473-4b23-887a-61b05f9341b4'

doc_id = re.search('DocID=(.*)', url).group(1)