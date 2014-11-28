<xsl:stylesheet xmlns:xsl="http://www.w3.org/1999/XSL/Transform" version="1.0">
    <xsl:template match="@*|node()" name="identity">
        <xsl:copy>
            <xsl:apply-templates select="@*|node()" />
        </xsl:copy>
    </xsl:template>
    <xsl:template match="installer-gui-script/*[1]">
        <options rootVolumeOnly="true"/>
        <xsl:text>&#xa;    </xsl:text>
        <domains enable_anywhere="false" enable_currentUserHome="false" enable_localSystem="true"/>
        <xsl:text>&#xa;    </xsl:text>
        <xsl:call-template name="identity" />
    </xsl:template>
</xsl:stylesheet>
