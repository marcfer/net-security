# ================
# Public Functions
# ================
library(XML)
library(gtools) #rbind.data.frame(xpath1[[1]], xpath1[[2]], ...) --- do.call(rbind.data.frame, xpath1)
parseXMLtoDF <- function(xml) {
  xmlTree <- xmlTreeParse("/Users/barri/Desktop/Universidad/Master/3. Data Driven Security/Rproject/net-security/data/cwec_v2.9.xml", useInternalNodes = TRUE)
  rootNode <- xmlRoot(xmlTree) #xmlName(rootNode) = Weakness_Catalog
  weaknessesNode <- rootNode[[3]] #weaknessesNode = Weaknesses
  xpath <- xpathApply(weaknessesNode, "//Weakness[@ID<'110']", xmlAttrs)
  dataFrame <- do.call(rbind.data.frame, xpath)
  names(dataFrame) <- c("ID", "Name", "Weakness_Abstraction", "Status")
}

# =================
# Private Functions
# =================
