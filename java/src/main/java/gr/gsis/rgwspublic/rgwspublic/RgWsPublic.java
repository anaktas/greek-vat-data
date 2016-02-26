
package gr.gsis.rgwspublic.rgwspublic;

import java.math.BigDecimal;
import javax.jws.WebMethod;
import javax.jws.WebParam;
import javax.jws.WebResult;
import javax.jws.WebService;
import javax.jws.soap.SOAPBinding;
import javax.xml.bind.annotation.XmlSeeAlso;
import javax.xml.ws.Holder;


/**
 * This class was generated by the JAX-WS RI.
 * JAX-WS RI 2.2.4-b01
 * Generated source version: 2.2
 * 
 */
@WebService(name = "RgWsPublic", targetNamespace = "http://gr/gsis/rgwspublic/RgWsPublic.wsdl")
@SOAPBinding(style = SOAPBinding.Style.RPC)
@XmlSeeAlso({
    ObjectFactory.class
})
public interface RgWsPublic {


    /**
     * 
     * @param arrayOfRgWsPublicFirmActRtOut
     * @param pCallSeqIdOut
     * @param rgWsPublicBasicRtOut
     * @param rgWsPublicInputRtIn
     * @param pErrorRecOut
     */
    @WebMethod(action = "http://gr/gsis/rgwspublic/RgWsPublic.wsdl/rgWsPublicAfmMethod")
    public void rgWsPublicAfmMethod(
        @WebParam(name = "RgWsPublicInputRt_in", partName = "RgWsPublicInputRt_in")
        RgWsPublicInputRtUser rgWsPublicInputRtIn,
        @WebParam(name = "RgWsPublicBasicRt_out", mode = WebParam.Mode.INOUT, partName = "RgWsPublicBasicRt_out")
        Holder<RgWsPublicBasicRtUser> rgWsPublicBasicRtOut,
        @WebParam(name = "arrayOfRgWsPublicFirmActRt_out", mode = WebParam.Mode.INOUT, partName = "arrayOfRgWsPublicFirmActRt_out")
        Holder<RgWsPublicFirmActRtUserArray> arrayOfRgWsPublicFirmActRtOut,
        @WebParam(name = "pCallSeqId_out", mode = WebParam.Mode.INOUT, partName = "pCallSeqId_out")
        Holder<BigDecimal> pCallSeqIdOut,
        @WebParam(name = "pErrorRec_out", mode = WebParam.Mode.INOUT, partName = "pErrorRec_out")
        Holder<GenWsErrorRtUser> pErrorRecOut);

    /**
     * 
     * @return
     *     returns java.lang.String
     */
    @WebMethod(action = "http://gr/gsis/rgwspublic/RgWsPublic.wsdl/rgWsPublicVersionInfo")
    @WebResult(name = "result", partName = "result")
    public String rgWsPublicVersionInfo();

}
