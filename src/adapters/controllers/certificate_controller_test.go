package controllers_test

import (
	"testing"

	"certigen/src/shared/testify"
)

func TestNfHttpController(ts *testing.T) {
	// ctx := context.Background()

	testify.It(ts, "Should return response with status 200", func(t *testing.T) {
		t.Skip()
		/*
			ctrl := gomock.NewController(t)
			ds := mocks.NewMockDataStore(ctrl)
			ds.EXPECT().Mysql().AnyTimes()
			ds.EXPECT().Postgres().AnyTimes()

			input := models.Nf{}
			input.Company = models.Company{CNPJ: cnpj}
			input.Competence = datetime.FromYearMonthStr(competence)
			nfService := mocks.NewMockNfService(ctrl)
			nfService.EXPECT().ReadAllForPisCalc(ctx, input).Return(output, nil)
			nfController := controllers.NewNfHttpController(ds)
			nfController.SetNfService(nfService)

			url := "/some/path"
			req := httpclient.New().DoGET(url)
			server := httpserver.OnGET("/cnpj/:cnpj/competence/:competence", nfController.ReadAllNfForPisCalc)
			var body out.HttpResponse
			res, err := server.ServeHTTP(req, &body)

			assert.Nil(t, err, fmt.Sprintf("Expected nil but got %s", err))
			assert.Equal(t, res.StatusCode, 200)

			var data []out.NfHttpResponse
			stringfy.FromJSON(body.DataJSON(), &data)
			assert.Equal(t, len(data), 1)
			assert.Equal(t, data[0].Amount, output[0].Amount)
			assert.Equal(t, data[0].Competence, competence)
		*/
	})
}
