cda="""<!-- <?xml version="1.0" encoding="UTF-8"?> -->
<ClinicalDocument xmlns="urn:hl7-org:v3" xmlns:mif="urn:hl7-org:v3/mif" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xmlns:lab="urn:oid:1.3.6.1.4.1.19376.1.3.2" xmlns:sdtc="urn:hl7-org:sdtc">
	<realmCode code="IT"/>
	<typeId root="2.16.840.1.113883.1.3" extension="POCD_MT000040UV02"/>
	<templateId root="2.16.840.1.113883.2.9.10.1.1" extension="1.3" assigningAuthorityName="HL7 Italia"/>
	<id root="2.16.840.1.113883.2.9.2.120.4.4" extension="030702.TSTSMN63A01F205H.20220325112426.OQlvTq1J" assigningAuthorityName="Regione Lazio"/>	
	<code 	code="11502-2"	codeSystem="2.16.840.1.113883.6.1"  codeSystemName="LOINC" displayName="Referto di laboratorio"/> 
	<title> REFERTO DI LABORATORIO</title>
	<sdtc:statusCode code="active"/>
	<effectiveTime value="20220330112426+0100"/>
	<confidentialityCode code="N" codeSystem="2.16.840.1.113883.5.25" codeSystemName="HL7 Confidentiality" displayName="Normal"/>
	<languageCode code="it-IT"/>
	<setId root="2.16.840.1.113883.2.9.2.120.4.4" extension="c030702.TSTSMN63A01F205H.20220325112426.TSS1Tkju" assigningAuthorityName="Regione Lazio"/> 
	<versionNumber value="2"/> 
	<recordTarget typeCode="RCT" contextControlCode="OP">
		<patientRole classCode="PAT">
			<id root="2.16.840.1.113883.2.9.4.3.2" extension="RSSMRA22A01A399Z" assigningAuthorityName="MEF"/> 
			<addr use="H"> 
				<country>100</country>
				<state>120</state>
				<county>RM</county> 
				<city>Roma</city> 
				<censusTract>058091</censusTract> 
				<postalCode>00187</postalCode> 
				<streetAddressLine>Via Aurora 12</streetAddressLine> 
			</addr> 
			<addr use="HP"> 
				<country>100</country>
				<state>120</state>
				<county>RM</county> 
				<city>Roma</city> 
				<censusTract>058091</censusTract> 
				<postalCode>00138</postalCode> 
				<streetAddressLine>Via Canevari 12B</streetAddressLine>
			</addr>			
			<telecom use="HP" value="mailto:giuseppe.verdi@gmail.com"/>
			<telecom use="MC" value="tel:33224456"/>
			<patient> 
				<name> 
					<family>Verdi</family> 
					<given>Giuseppe</given> 
				</name> 
				<administrativeGenderCode code="M" codeSystem="2.16.840.1.113883.5.1" codeSystemName="HL7 AdministrativeGender" displayName="MASCHIO"/> 
				<birthTime value="19930619"/>
				<birthplace> 
					<place>
						<addr>
							<country>100</country>
							<state>120</state>
							<county>RM</county> 
							<city>Roma</city> 
							<censusTract>058091</censusTract>
						</addr>					
					</place> 
				</birthplace> 
			</patient>
		</patientRole>
	</recordTarget>
	<author> 
		<time value="20220325110000+0100"/>
		<assignedAuthor classCode="ASSIGNED"> 
			<id root="2.16.840.1.113883.2.9.4.3.2" extension="MTCORV58E63L294G" assigningAuthorityName="MEF"/> 
			<addr>
				<country>100</country>
				<state>120</state>
				<county>RM</county> 
				<city>Roma</city> 
				<censusTract>058091</censusTract> 
				<postalCode>00184</postalCode> 
				<streetAddressLine>Via Milano 7</streetAddressLine>
			</addr>
			<telecom use="HP" value="mailto:matteo.cervone@gmail.it"/> 
			<telecom use="WP" value="mailto:matteo.cervone@pec.it"/> 
			<telecom use="MC" value="tel:3478129873"/>
			<assignedPerson> 
				<name> 
					<family>Cervone</family> 
					<given>Matteo</given> 
					<prefix>Dr</prefix>
				</name> 
			</assignedPerson>
		</assignedAuthor> 
	</author> 
	
	<dataEnterer typeCode="ENT"> 
		<time value="20220325120000+0100"/> 
		<assignedEntity> 
			<id root="2.16.840.1.113883.2.9.4.3.2" extension="FPSSBN85G54D398H" assigningAuthorityName="MEF"/> 
			<assignedPerson> 
				<name> 
					<family>Mancusi</family> 
					<given>Filippo</given> 
				</name> 
			</assignedPerson> 
		</assignedEntity> 
	</dataEnterer>

	<custodian> 
		<assignedCustodian> 
			<representedCustodianOrganization>
				<id root="2.16.840.1.113883.2.9.4.1.2" extension="120148" assigningAuthorityName="Ministero della Salute"/>	
				<name>SAN RAFFAELE NOMENTANA</name>
				<telecom use="HP" value="tel: 390 666 0581"/> 
				<addr> 
					<country>100</country>
					<state>120</state>
					<county>RM</county> 
					<city>Roma</city> 
					<censusTract>058091</censusTract>
					<postalCode>00137</postalCode> 
					<streetAddressLine>Via Emilio Praga 39</streetAddressLine> 
				</addr>				
			</representedCustodianOrganization> 
		</assignedCustodian> 
	</custodian> 
	<informationRecipient> 
		<intendedRecipient> 
			<id root="2.16.840.1.113883.2.9.4.3.2" extension="MURRSI88Y67R012G" assigningAuthorityName="MEF"/> 
			<telecom use="WP" value="tel:062866794"/> 
			<informationRecipient> 
				<name>
					<family>Rossi</family> 
					<given>Maura</given> 
				</name> 
			</informationRecipient> 
		</intendedRecipient> 
	</informationRecipient> 

	<legalAuthenticator> 
		<time value="20220325110000+0100"/> 
			<signatureCode code="S"/> 
			<assignedEntity>
				<id root="2.16.840.1.113883.2.9.4.3.2" extension="GPSDGK80E76C765V" assigningAuthorityName="MEF"/> 
				<addr> 
					<country>100</country>
					<state>120</state>
					<county>RM</county> 
					<city>Roma</city> 
					<censusTract>058091</censusTract> 
					<postalCode>00164</postalCode> 
					<streetAddressLine>Via Corvetto 3</streetAddressLine>
				</addr> 
				<telecom use="HP" value="mailto:righi.federico@gmail.com"/> 
				<telecom use="MC" value="tel:330987986"/> 
				<assignedPerson> 
					<name>  
						<family>Righi</family> 
						<given>Federico</given>
						<prefix>Dttr.</prefix>
					</name> 
				</assignedPerson> 
			</assignedEntity> 
	</legalAuthenticator> 
	
	<authenticator> 
		<time value="20220325110000+0100"/> 
		<signatureCode code="S"/> 
		<assignedEntity> 
			<id root="2.16.840.1.113883.2.9.4.3.2" extension="RBTAMA67H99H467D" assigningAuthorityName="MEF"/> 
			<addr> 
				<country>100</country>
				<state>120</state>
				<county>RM</county> 
				<city>Roma</city> 
				<censusTract>058091</censusTract> 
				<postalCode>00164</postalCode> 
				<streetAddressLine>Via Corvetto 3</streetAddressLine>
			</addr> 
			<telecom use="HP" value="mailto:maggi.roberta@gmail.com"/> 
			<telecom use="HP" value="tel:22998276800"/> 
			<assignedPerson> 
				<name> 
					<family>Rossi</family> 
					<given>Roberta</given> 
				</name> 
			</assignedPerson>
		</assignedEntity> 
	</authenticator> 
		
	<participant typeCode="REF" contextControlCode="OP">
		<functionCode code="PRE" codeSystem= "2.16.840.1.113883.2.9.5.1.88"/>  
		<time value="20220320110000+0100"/> 	
		<associatedEntity classCode="QUAL">
			<id root="2.16.840.1.113883.2.9.4.3.2" extension="STVMG77F45N079MF" assigningAuthorityName="MEF"/>
			<addr>
				<country>100</country>
				<state>120</state>
				<county>RM</county> 
				<city>Roma</city> 
				<censusTract>058091</censusTract> 
				<postalCode>00187</postalCode> 
				<streetAddressLine>Via Vittorio Veneto 3</streetAddressLine>
			</addr>
			<telecom use="HP" value="mailto:maggi.silvia@gmail.com"/>
			<associatedPerson>
				<name>
					<family>Maggi</family>
					<given>Silvia</given>
				</name>
			</associatedPerson>
			<scopingOrganization>
				<id root="2.16.840.1.113883.2.9.4.1.2" extension="120148" assigningAuthorityName="Ministero della Salute"/><!-- STS11-->
				<name></name>
				<name>SAN RAFFAELE NOMENTANA</name>
				<telecom use="HP" value="tel: 390 666 0581"/> 
				<addr> 
					<country>100</country>
					<state>120</state>
					<county>RM</county> 
					<city>Roma</city> 
					<censusTract>058091</censusTract>
					<postalCode>00137</postalCode> 
					<streetAddressLine>Via Emilio Praga 39</streetAddressLine> 
				</addr>	
			</scopingOrganization>
		</associatedEntity>
	</participant>
	
	<inFulfillmentOf> 
		<order classCode="ACT" moodCode="RQO"> 
			<id root="2.16.840.1.113883.2.9.4.3.9" extension="[NRE]" assigningAuthorityName="Ministero delle Finanze"/> 
			<priorityCode code="P" codeSystem="2.16.840.1.113883.5.7" codeSystemName="HL7 ActPriority" displayName="routine"/>
		</order> 
	</inFulfillmentOf> 
	
	<documentationOf>
		<serviceEvent moodCode="EVN">
			<statusCode code="completed"/>
			<effectiveTime value="20220324112426+0100"/>
			<performer typeCode="PRF">
				<assignedEntity>
					<id root="2.16.840.1.113883.2.9.4.3.2" extension="MRSSIO79H59Z317K" assigningAuthorityName="MEF"/>
					<assignedPerson>
						<name>
							<family>Rossi</family>
							<given>Mario</given>
						</name>
					</assignedPerson>
					<representedOrganization>
						<id root="2.16.840.1.113883.2.9.4.1.3" extension="327700102" assigningAuthorityName="Ministero della Salute"/>
						<name>Nuovo Ospedale S.Agostino (MO)</name>
						<asOrganizationPartOf>
							<id root="2.16.840.1.113883.2.9.4.1.1" extension="080105" assigningAuthorityName="Ministero della Salute"/>
						</asOrganizationPartOf>	
					</representedOrganization>
				</assignedEntity>
			</performer>
		</serviceEvent>
	</documentationOf>
	
	<relatedDocument typeCode ="RPLC"> 
		<parentDocument> 
			<id root="2.16.840.1.113883.2.9.2.120.4.4" extension="030702.TSTSMN63A01F205H.20220330112426.TSS1Tkju" assigningAuthorityName="Regione Lazio"/>
			<setId root="2.16.840.1.113883.2.9.2.120.4.4" extension="c030702.TSTSMN63A01F205H.20220325112426.TSS1Tkju" assigningAuthorityName="Regione Lazio"/>
			<versionNumber value="1"/> 
		</parentDocument> 
	</relatedDocument> 
	
	<componentOf>
		<encompassingEncounter>
			<effectiveTime value="20220330112426+0100"/>
			<responsibleParty>
				<assignedEntity>
					<id root="2.16.840.1.113883.2.9.4.3.2" extension="SVATPR85Y37T079B" assigningAuthorityName="MEF"/>
					<assignedPerson>
						<name>
							<family>Turri</family>
							<given>Silvia</given>
						</name>
					</assignedPerson>
				</assignedEntity>
			</responsibleParty>
			<location>
				<healthCareFacility>
					<id root="2.16.840.1.113883.2.9.4.1.6" extension="XXX" assigningAuthorityName="Ministero della Salute"/>
					<serviceProviderOrganization>
						<id root="2.16.840.1.113883.2.9.4.1.2" extension="XXX" assigningAuthorityName="Ministero della Salute"/>
						<name>[nome_presidio]</name>
						<telecom use="HP" value="tel:0115678965"/>
						<asOrganizationPartOf>
							<id root="2.16.840.1.113883.2.9.4.1.1" extension="XXX" assigningAuthorityName="Ministero della Salute"/>
						</asOrganizationPartOf>
					</serviceProviderOrganization>
				</healthCareFacility>
			</location>
		</encompassingEncounter>
	</componentOf>


	<!-- Structured body -->
	<component>
		<structuredBody>
			<component>
				<section ID="ESAMI_URINE">
					<code code="18729-4" codeSystem="2.16.840.1.113883.6.1" codeSystemName="LOINC" displayName="ESAMI DELLE URINE"/>
					<title>Esami delle Urine</title>
					<component>
						<section ID="ALBUMINA_URINE">
							<code code="14957-5" codeSystem="2.16.840.1.113883.6.1" codeSystemName="LOINC" displayName="Microalbumin Massa/Volume in Urine">
								<translation code="0090334.02" codeSystem="2.16.840.1.113883.2.9.2.30.6.11" codeSystemName="SISS" displayName="Microalbumina nelle urine"/>
							</code>
							<title>Albumina nelle Urine</title>
							<text>
								<list>
									<item>
										<table ID="nota1">
											<thead>
												<tr>
													<th>Esame</th>
													<th>Metodo utilizzato per l'esame</th>
													<th>Materiale utilizzato per l'esame</th>
													<th>Risultato dell'esame</th>
													<th>Commenti e note</th>
													<th>Unità di Misura</th>
													<th>Range di Riferimento</th>
													<th>Criteri per il range di riferimento</th>
													<th>Interpretazione</th>
													<th>Allegati multimediali</th>
												</tr>
											</thead>
											<tbody>
												<tr>
													<td>Microalbumina massa/volume in urine</td>
													<td></td>
													<td>Urine</td>
													<td>20</td>
													<td></td>
													<td>mg/L</td>
													<td> 0 - 20 </td>
													<td></td>
													<td>N</td>
													<td/>
												</tr>
											</tbody>
										</table>
									</item>
								</list>
							</text>
							<entry typeCode="DRIV">
								<act moodCode="EVN" classCode="ACT">
									<code code="14957-5" codeSystem="2.16.840.1.113883.6.1" codeSystemName="LOINC" displayName="Microalbumin Massa/Volume in Urine"/>	
									<statusCode code="active"/>
									<specimen>			
										<specimenRole>
											<specimenPlayingEntity>
												<code code="UR" codeSystem="2.16.840.1.113883.5.129" codeSystemName="SpecimenType " displayName="Urine"/>
											</specimenPlayingEntity>
										</specimenRole>
									</specimen>
									<entryRelationship typeCode="SUBJ">
										<act moodCode="EVN" classCode="ACT">
											<code code="48767-8" codeSystem="2.16.840.1.113883.6.1" codeSystemName="LOINC" displayName="Annotazioni e commenti"/>
											<text>
												<reference value="#nota1"/>
											</text>
										</act>
									</entryRelationship>
									
									<entryRelationship typeCode="COMP">
										<observation moodCode="EVN" classCode="OBS">
											<code code="14957-5" codeSystem="2.16.840.1.113883.6.1" codeSystemName="LOINC" displayName="Microalbumin Massa/Volume in Urine">
												<translation code="0090334.02" codeSystem="2.16.840.1.113883.2.9.2.30.6.11" codeSystemName="SISS" displayName="Albumina nelle urine"/>
											</code>									
											<statusCode code="completed"/>
											<effectiveTime value="20220330112426+0100"/>
											<value xsi:type="PQ" value="16.00" unit="mg/L"/>
											<interpretationCode code="N" codeSystem="2.16.840.1.113883.5.83" codeSystemName="HL7 Observation Interpretation" displayName="Normal"/>
											<specimen typeCode="SPC">
												<specimenRole classCode="SPEC">
													<specimenPlayingEntity>
														<code code="UR" codeSystem="2.16.840.1.113883.5.129" codeSystemName="SpecimenType" displayName="Urine"/>
													</specimenPlayingEntity>
												</specimenRole>
											</specimen>
											<referenceRange>
												<observationRange>
													<value xsi:type="IVL_PQ">
														<low value=" 0.00" unit="mg/L"/>
														<high value=" 20.00" unit="mg/L"/>
													</value>
													<interpretationCode code="N" codeSystem="2.16.840.1.113883.5.83" codeSystemName="HL7 Observation Interpretation" displayName="Normal"/>
													<lab:precondition> 
														<lab:criterion>
															<lab:code code="30525-0" codeSystem="2.16.840.1.113883.6.1" codeSystemName="LOINC" displayName="Età"/>
															<lab:value xsi:type="IVL_PQ"> 
																<high value="60" unit="a"/>
															</lab:value>
														</lab:criterion>
													</lab:precondition>
												</observationRange>
											</referenceRange>
										</observation>
									</entryRelationship>
								</act>	
							</entry>
						</section>					
					</component>
				</section>	
			</component>
		</structuredBody>	
	</component>
</ClinicalDocument>"""